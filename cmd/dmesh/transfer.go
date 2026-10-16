package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/clock"
	"github.com/MonkeyIsNull/DMesh/internal/discovery"
	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/node"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

// cmdSend opens a durable session to a peer by node ID and streams a file over
// it with io.Copy. The session survives a transport drop / roam and resumes from
// the exact byte offset, so the transfer completes intact even if connectivity
// blips mid-stream. On completion it prints the SHA-256 so a human can confirm
// the bytes are identical on both ends.
func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	label := fs.String("label", "", "human label for this node")
	port := fs.Int("port", 0, "UDP port to listen on (0 = ephemeral)")
	noMDNS := fs.Bool("no-mdns", false, "disable mDNS discovery")
	chaos := fs.Bool("chaos", false, "rebind the local UDP socket mid-stream to force a pause/resume")
	var peers addrList
	fs.Var(&peers, "peer", "dial this peer directly, IP:PORT (repeatable; bypasses mDNS)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New("usage: dmesh send <node-id> <file> [--chaos]")
	}
	peer, err := identity.ParseNodeID(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("bad node id: %w", err)
	}
	path := fs.Arg(1)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}

	n, cleanup, err := buildNode(*label, *port, *noMDNS, peers)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	errCh := make(chan error, 1)
	go func() { errCh <- n.Run(ctx) }()
	go func() { <-sigCh; cancel() }()

	fmt.Printf("dmesh send: %s (%d bytes) -> %s\n", filepath.Base(path), fi.Size(), peer.Short())
	fmt.Printf("  opening durable session (dialing by identity)...\n")

	sess, err := n.OpenSession(ctx, peer)
	if err != nil {
		return err
	}

	if *chaos {
		go runChaos(ctx, n, *port)
	}
	go reportProgress(ctx, sess)

	h := sha256.New()
	tee := io.TeeReader(f, h)
	copied, cerr := io.Copy(sess, tee)
	if cerr != nil {
		return fmt.Errorf("transfer failed: %w", cerr)
	}
	if err := sess.CloseWrite(); err != nil {
		return err
	}
	// Wait for the receiver to drain + ack the FIN (session done) or ctx cancel.
	select {
	case <-sess.Done():
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
	}
	fmt.Printf("  sent %d bytes\n", copied)
	fmt.Printf("  sha256: %x\n", h.Sum(nil))
	cancel()
	<-errCh
	return nil
}

// cmdRecv accepts one inbound durable session, streams it to a file, and prints
// the SHA-256 so it can be compared with the sender's.
func cmdRecv(args []string) error {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	label := fs.String("label", "", "human label for this node")
	port := fs.Int("port", 0, "UDP port to listen on (0 = ephemeral)")
	noMDNS := fs.Bool("no-mdns", false, "disable mDNS discovery")
	out := fs.String("out", ".", "directory to write the received file to")
	var peers addrList
	fs.Var(&peers, "peer", "dial this peer directly, IP:PORT (repeatable; bypasses mDNS)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	n, cleanup, err := buildNode(*label, *port, *noMDNS, peers)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	errCh := make(chan error, 1)
	go func() { errCh <- n.Run(ctx) }()
	go func() { <-sigCh; cancel() }()

	fmt.Printf("dmesh recv: node %s listening on %s\n", n.SelfID().Short(), n.LocalAddr())
	fmt.Printf("  waiting for an inbound session...\n")

	var sess *node.Session
	select {
	case sess = <-n.Accept():
	case <-ctx.Done():
		return nil
	}
	fmt.Printf("  accepted session from %s\n", sess.Peer().Short())

	outPath := filepath.Join(*out, fmt.Sprintf("dmesh-recv-%s.bin", sess.Peer().Short()))
	wf, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer wf.Close()

	h := sha256.New()
	w := io.MultiWriter(wf, h)
	copied, cerr := io.Copy(w, sess)
	if cerr != nil && cerr != io.EOF {
		return fmt.Errorf("receive failed: %w", cerr)
	}
	// Half-close our (empty) send direction so the sender sees a clean
	// bidirectional close and both sessions reach a terminal state (freeing
	// buffers + the session slot) rather than lingering until grace.
	if err := sess.CloseWrite(); err != nil {
		return err
	}
	// Wait for the clean close to complete (both FINs exchanged) or ctx cancel.
	select {
	case <-sess.Done():
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
	}
	fmt.Printf("  received %d bytes -> %s\n", copied, outPath)
	fmt.Printf("  sha256: %x\n", h.Sum(nil))
	cancel()
	<-errCh
	return nil
}

// reportProgress prints the live byte offset and pause/resume transitions.
func reportProgress(ctx context.Context, sess *node.Session) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	last := node.SessionStatus{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.Done():
			return
		case <-t.C:
			st := sess.Status()
			if st.State != last.State {
				switch st.State {
				case "paused":
					fmt.Printf("  paused at offset %d (peer alive per SWIM; within grace)\n", st.SndUna)
				case "resuming":
					fmt.Printf("  resuming from offset %d\n", st.SndUna)
				case "established":
					if last.State == "resuming" || last.State == "paused" {
						fmt.Printf("  resumed; offset %d\n", st.SndUna)
					}
				}
			}
			last = st
		}
	}
}

// runChaos rebinds the local UDP socket mid-stream to force the transport to
// drop and re-handshake, exercising the real pause/resume path on one machine.
func runChaos(ctx context.Context, n *node.Node, port int) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Second):
	}
	conn, err := transport.ListenUDP(0) // fresh ephemeral socket => new endpoint => roam
	if err != nil {
		return
	}
	fmt.Printf("  [chaos] rebinding local socket -> %s\n", conn.LocalAddr())
	n.RebindConnForTest(conn)
}

// buildNode constructs a node with the real clock, mandatory network key, and
// (optionally) mDNS discovery. Any static seed endpoints are dialed directly,
// bypassing discovery. The returned cleanup closes discovery.
func buildNode(label string, port int, noMDNS bool, seeds []netip.AddrPort) (*node.Node, func(), error) {
	c, err := openConfig()
	if err != nil {
		return nil, nil, err
	}
	id, _, err := c.LoadIdentity(label)
	if err != nil {
		return nil, nil, err
	}
	psk, err := c.LoadNetworkKey()
	if err != nil {
		return nil, nil, err
	}
	if len(psk) == 0 {
		return nil, nil, errors.New("no network key configured; run 'dmesh network-key gen' (fail closed)")
	}
	trusted, err := loadTrustedSet(c)
	if err != nil {
		return nil, nil, err
	}
	conn, err := transport.ListenUDP(port)
	if err != nil {
		return nil, nil, err
	}
	var disc discovery.Discovery
	cleanup := func() { _ = conn.Close() }
	if !noMDNS {
		md := discovery.NewMDNS()
		disc = md
		cleanup = func() { _ = md.Close(); _ = conn.Close() }
	}
	n, err := node.New(node.Config{
		Identity:         id,
		NetworkPSK:       psk,
		Policy:           transport.AllowList(trusted, false),
		Discovery:        disc,
		Conn:             conn,
		Clock:            clock.Real{},
		EnforceAllowList: len(trusted) > 0,
		IncarnationPath:  c.IncarnationPath(),
		SeedPeers:        seeds,
	})
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return n, cleanup, nil
}
