package node

import (
	"context"
	"errors"
	"io"

	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/session"
)

// errTooManySessions is returned by OpenSession when a session cap is hit.
var errTooManySessions = errors.New("node: session cap reached")

// Session is the public, identity-addressed, net.Conn-shaped handle to a durable
// session. Read/Write/CloseWrite/Close are called by app goroutines and talk to
// the single-owner loop by channel; the loop owns the reliable-stream engine.
// The net.Conn shape lets io.Copy "just work" and is deliberately chosen so the
// later session-host milestone can sit a pty/program on top with no protocol
// change.
type Session struct {
	node *Node
	id   session.SessionID
	peer identity.NodeID
	ls   *liveSession
}

// ID returns the session id.
func (s *Session) ID() session.SessionID { return s.id }

// Peer returns the authenticated peer identity this session is anchored to.
func (s *Session) Peer() identity.NodeID { return s.peer }

// Done is closed when the session terminates (clean close, grace timeout, peer
// gone, or reset).
func (s *Session) Done() <-chan struct{} { return s.ls.done }

// Err returns the terminal error, or nil while the session is live.
func (s *Session) Err() error {
	s.node.mu.RLock()
	defer s.node.mu.RUnlock()
	return s.ls.err
}

// Read returns in-order stream bytes. It blocks until bytes are available, EOF
// after the peer's FIN is fully delivered, or the terminal error on teardown.
func (s *Session) Read(p []byte) (int, error) {
	for {
		s.node.mu.Lock()
		if len(s.ls.readBuf) > 0 {
			n := copy(p, s.ls.readBuf)
			s.ls.readBuf = s.ls.readBuf[n:]
			s.node.mu.Unlock()
			s.ackRead(n)
			return n, nil
		}
		eof := s.ls.eof
		closed := s.ls.closed
		err := s.ls.err
		s.node.mu.Unlock()
		if eof {
			return 0, io.EOF
		}
		if closed {
			if err == nil {
				err = session.ErrClosed
			}
			return 0, err
		}
		select {
		case <-s.ls.readWake:
		case <-s.ls.done:
		}
	}
}

// Write reliably and in-order sends p. It blocks on a full send window
// (backpressure) until an ACK frees space. It returns the terminal error if the
// session is torn down mid-write.
func (s *Session) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		reply := make(chan sessCtlResp, 1)
		s.node.sbAdd()
		select {
		case s.node.sessCtl <- sessCtlReq{kind: ctlWrite, id: s.id, data: p, reply: reply}:
		case <-s.ls.done:
			s.node.sbDone()
			return total, s.terminalErr()
		case <-s.node.runCtx.Done():
			s.node.sbDone()
			return total, context.Canceled
		}
		resp := <-reply
		if resp.err != nil {
			return total, resp.err
		}
		total += resp.n
		p = p[resp.n:]
		if resp.n == 0 {
			select {
			case <-s.ls.writeWake:
			case <-s.ls.done:
				return total, s.terminalErr()
			case <-s.node.runCtx.Done():
				return total, context.Canceled
			}
		}
	}
	return total, nil
}

// CloseWrite half-closes the send direction (FIN); the peer sees EOF once all
// bytes through the final offset are delivered.
func (s *Session) CloseWrite() error {
	return s.ctl(ctlCloseWrite)
}

// Close tears the session down locally (RESET to the peer).
func (s *Session) Close() error {
	return s.ctl(ctlClose)
}

func (s *Session) ctl(kind ctlKind) error {
	reply := make(chan sessCtlResp, 1)
	s.node.sbAdd()
	select {
	case s.node.sessCtl <- sessCtlReq{kind: kind, id: s.id, reply: reply}:
	case <-s.ls.done:
		s.node.sbDone()
		return nil
	case <-s.node.runCtx.Done():
		s.node.sbDone()
		return context.Canceled
	}
	resp := <-reply
	return resp.err
}

// ackRead tells the loop the app consumed n bytes so the receive window reopens.
// Fire-and-forget (no reply).
func (s *Session) ackRead(n int) {
	s.node.sbAdd()
	select {
	case s.node.sessCtl <- sessCtlReq{kind: ctlReadAck, id: s.id, n: n}:
	case <-s.ls.done:
		s.node.sbDone()
	case <-s.node.runCtx.Done():
		s.node.sbDone()
	}
}

func (s *Session) terminalErr() error {
	s.node.mu.RLock()
	defer s.node.mu.RUnlock()
	if s.ls.err != nil {
		return s.ls.err
	}
	return session.ErrClosed
}

// --- public Node API --------------------------------------------------------

// OpenSession opens a durable, reliable, ordered session to a peer by node ID.
// It dials the peer by identity if no transport exists yet; the OPEN is
// (re)transmitted once the transport binds. The returned handle is usable
// immediately (writes buffer behind the send window).
func (n *Node) OpenSession(ctx context.Context, peer identity.NodeID) (*Session, error) {
	sid, err := session.NewSessionID()
	if err != nil {
		return nil, err
	}
	reply := make(chan sessCtlResp, 1)
	n.sbAdd()
	select {
	case n.sessCtl <- sessCtlReq{kind: ctlOpen, peer: peer, id: sid, reply: reply}:
	case <-ctx.Done():
		n.sbDone()
		return nil, ctx.Err()
	}
	select {
	case resp := <-reply:
		if resp.err != nil {
			return nil, resp.err
		}
		return resp.handle, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Accept returns the channel of inbound sessions (bounded backlog). The app
// ranges over it to serve incoming durable sessions.
func (n *Node) Accept() <-chan *Session { return n.accept }

// SessionStatus is a point-in-time view of a session's state and cursors, for
// status rendering / progress reporting.
type SessionStatus struct {
	State  string
	SndUna uint64
	RcvNxt uint64
}

// Status returns a race-free snapshot of the session (resolved in the loop).
func (s *Session) Status() SessionStatus {
	reply := make(chan sessCtlResp, 1)
	s.node.sbAdd()
	select {
	case s.node.sessCtl <- sessCtlReq{kind: ctlStatus, id: s.id, reply: reply}:
	case <-s.ls.done:
		s.node.sbDone()
		return SessionStatus{State: "closed"}
	case <-s.node.runCtx.Done():
		s.node.sbDone()
		return SessionStatus{State: "closed"}
	}
	select {
	case resp := <-reply:
		return resp.status
	case <-s.ls.done:
		return SessionStatus{State: "closed"}
	}
}
