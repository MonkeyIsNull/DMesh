package transport

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/clock"
	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/flynn/noise"
)

// Noise parameters: Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s.
//
// XX is correct for DMesh because discovery hints are unauthenticated and
// LAN-spoofable, so each side must learn AND verify the peer static in-band
// (exactly what XX does), and mesh roles are symmetric (IK/KK bake in an
// asymmetry and need the peer static known in advance). psk0 mixes the network
// key from message 1, so a wrong/absent key fails the AEAD at msg1 - the
// cheapest rejection.

// prologue is a domain-separated prologue binding the proto version into the
// transcript. It must match on both sides or the handshake fails.
var prologue = []byte("DMesh-v1 prologue")

// bindingLen is the length of the identity-binding payload carried inside the
// AEAD-protected payloads of msg2 (responder) and msg3 (initiator):
// Ed25519 pubkey (32) || Ed25519 signature (64).
const bindingLen = ed25519.PublicKeySize + ed25519.SignatureSize

func cipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
}

// bindingPayload builds the identity-binding bytes for an identity.
func bindingPayload(id *identity.Identity) []byte {
	edPub := id.Signing.Public().(ed25519.PublicKey)
	out := make([]byte, 0, bindingLen)
	out = append(out, edPub...)
	out = append(out, id.SignBinding()...)
	return out
}

// verifyBindingPayload checks a received binding payload against the X25519
// static that Noise authenticated (peerStatic). It returns the peer's node ID
// and Ed25519 public key on success.
func verifyBindingPayload(payload, peerStatic []byte) (identity.NodeID, ed25519.PublicKey, error) {
	if len(payload) != bindingLen {
		return identity.NodeID{}, nil, errors.New("transport: bad binding payload length")
	}
	edPub := ed25519.PublicKey(payload[:ed25519.PublicKeySize])
	sig := payload[ed25519.PublicKeySize:]
	if !identity.VerifyBinding(edPub, peerStatic, sig) {
		return identity.NodeID{}, nil, errors.New("transport: identity binding signature invalid")
	}
	var nid identity.NodeID
	copy(nid[:], edPub)
	cp := make(ed25519.PublicKey, len(edPub))
	copy(cp, edPub)
	return nid, cp, nil
}

// HandshakeResult carries everything produced by a completed handshake.
type HandshakeResult struct {
	Send       *noise.CipherState
	Recv       *noise.CipherState
	PeerNodeID identity.NodeID
	PeerEd     ed25519.PublicKey
	PeerStatic []byte
	LocalIndex uint32
	PeerIndex  uint32
	// FirstPayload is the decrypted payload of the responder's first data frame
	// (the initiator confirms msg3 delivery by receiving it). Nil for the
	// responder role.
	FirstPayload []byte
	// FirstNonce is the wire nonce of that first data frame, and HasFirst reports
	// that one was consumed. NewSession seeds the replay window with it so the
	// frame is covered by the same per-epoch replay protection as the rest.
	FirstNonce uint64
	HasFirst   bool
}

// Sender sends a single datagram to the peer.
type Sender interface {
	Send(datagram []byte) error
}

// retransmit policy.
const (
	defaultRTO = 250 * time.Millisecond
	maxRTO     = 2 * time.Second
	maxTries   = 8
)

// DoInitiator runs the initiator side of the handshake with stop-and-wait
// retransmit. inbox delivers raw datagrams the node demuxed to this handshake.
func DoInitiator(ctx context.Context, clk clock.Clock, snd Sender, inbox <-chan []byte,
	self *identity.Identity, psk []byte, localIndex uint32) (*HandshakeResult, error) {

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite(),
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      prologue,
		PresharedKey:  psk,
		StaticKeypair: self.NoiseStatic,
	})
	if err != nil {
		return nil, fmt.Errorf("transport: init handshake: %w", err)
	}

	// msg1: -> e
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("transport: write msg1: %w", err)
	}
	frame1 := encodeHandshake(1, localIndex, msg1)

	// Send msg1, retransmit until msg2 arrives. Verified peer identity is
	// captured in these locals (never package globals; many initiator
	// handshakes run concurrently).
	var (
		peerIndex  uint32
		peerNodeID identity.NodeID
		peerEd     ed25519.PublicKey
		got2       bool
	)
	err = stopAndWait(ctx, clk, snd, inbox, frame1, func(b []byte) (bool, error) {
		hf, derr := asHandshake(b)
		if derr != nil || hf.hsIndex != 2 {
			return false, nil // ignore anything but msg2
		}
		// msg2: <- e, ee, s, es  (payload = responder binding)
		payload, _, _, rerr := hs.ReadMessage(nil, hf.noiseMsg)
		if rerr != nil {
			return false, fmt.Errorf("transport: read msg2: %w", rerr)
		}
		nid, edPub, verr := verifyBindingPayload(payload, hs.PeerStatic())
		if verr != nil {
			return false, verr
		}
		peerIndex = hf.senderIndex
		peerNodeID = nid
		peerEd = edPub
		got2 = true
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if !got2 {
		return nil, errors.New("transport: handshake aborted before msg2")
	}

	// msg3: -> s, se  (payload = initiator binding). Completing yields cipher
	// states for the initiator.
	msg3, csSend, csRecv, err := hs.WriteMessage(nil, bindingPayload(self))
	if err != nil {
		return nil, fmt.Errorf("transport: write msg3: %w", err)
	}
	if csSend == nil || csRecv == nil {
		return nil, errors.New("transport: msg3 did not complete handshake")
	}
	frame3 := encodeHandshake(3, localIndex, msg3)

	// MUST-FIX msg3-loss recovery: a data frame can never ack msg3 for the
	// responder, but the responder's first authenticated frame IS the real ack
	// of msg3 for us. Cache frame3 and retransmit it until that frame arrives;
	// on a duplicate msg2, resend msg3.
	var (
		first      []byte
		firstNonce uint64
	)
	err = stopAndWait(ctx, clk, snd, inbox, frame3, func(b []byte) (bool, error) {
		ft, ferr := frameType(b)
		if ferr != nil {
			return false, nil
		}
		if ft == typeHandshake {
			// Likely a retransmitted msg2 (responder hasn't seen msg3 yet);
			// keep resending msg3 (stopAndWait does that on the next tick).
			return false, nil
		}
		// A data frame: the responder completed and sent its first frame.
		df, derr := decodeData(b)
		if derr != nil {
			return false, nil
		}
		csRecv.SetNonce(df.nonce)
		pt, aerr := csRecv.Decrypt(nil, nil, df.ciphertext)
		if aerr != nil {
			return false, nil // not the ack; drop and keep waiting
		}
		first = pt
		firstNonce = df.nonce
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	return &HandshakeResult{
		Send:         csSend,
		Recv:         csRecv,
		PeerNodeID:   peerNodeID,
		PeerEd:       peerEd,
		PeerStatic:   hs.PeerStatic(),
		LocalIndex:   localIndex,
		PeerIndex:    peerIndex,
		FirstPayload: first,
		FirstNonce:   firstNonce,
		HasFirst:     true,
	}, nil
}

// DoResponder runs the responder side with retransmit of msg2 until msg3
// arrives. It returns once the handshake completes; the caller then sends the
// first authenticated frame (HELLO), which acks msg3 for the initiator.
func DoResponder(ctx context.Context, clk clock.Clock, snd Sender, inbox <-chan []byte,
	self *identity.Identity, psk []byte, localIndex uint32) (*HandshakeResult, error) {

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite(),
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		Prologue:      prologue,
		PresharedKey:  psk,
		StaticKeypair: self.NoiseStatic,
	})
	if err != nil {
		return nil, fmt.Errorf("transport: init handshake: %w", err)
	}

	// Await msg1 (no retransmit by us; the initiator drives it).
	var peerIndex uint32
	msg1Frame, err := awaitHandshake(ctx, clk, inbox, func(hf handshakeFrame) bool {
		return hf.hsIndex == 1
	})
	if err != nil {
		return nil, err
	}
	peerIndex = msg1Frame.senderIndex
	if _, _, _, rerr := hs.ReadMessage(nil, msg1Frame.noiseMsg); rerr != nil {
		// Wrong/absent PSK fails the AEAD here - the cheapest rejection.
		return nil, fmt.Errorf("transport: read msg1 (credential check): %w", rerr)
	}

	// msg2: <- e, ee, s, es (payload = responder binding).
	msg2, _, _, err := hs.WriteMessage(nil, bindingPayload(self))
	if err != nil {
		return nil, fmt.Errorf("transport: write msg2: %w", err)
	}
	frame2 := encodeHandshake(2, localIndex, msg2)

	// Retransmit msg2 until msg3 arrives. A duplicate msg1 => resend msg2
	// (handled implicitly by continuing to retransmit). An undecryptable data
	// frame (initiator sent HELLO but we have no keys yet) => drop, keep going.
	var result *HandshakeResult
	err = stopAndWait(ctx, clk, snd, inbox, frame2, func(b []byte) (bool, error) {
		ft, ferr := frameType(b)
		if ferr != nil {
			return false, nil
		}
		if ft == typeData {
			return false, nil // can't be decrypted yet; drop
		}
		hf, derr := decodeHandshake(b)
		if derr != nil {
			return false, nil
		}
		if hf.hsIndex != 3 {
			return false, nil // dup msg1, etc. - keep resending msg2
		}
		// msg3: -> s, se (payload = initiator binding). Completing yields
		// cipher states for the responder.
		payload, csRecvMsg, csSendMsg, rerr := hs.ReadMessage(nil, hf.noiseMsg)
		if rerr != nil {
			return false, fmt.Errorf("transport: read msg3: %w", rerr)
		}
		if csRecvMsg == nil || csSendMsg == nil {
			return false, errors.New("transport: msg3 did not complete handshake")
		}
		nid, edPub, verr := verifyBindingPayload(payload, hs.PeerStatic())
		if verr != nil {
			return false, verr
		}
		// For the responder, ReadMessage returns (cs0=send-from-responder? ...).
		// flynn/noise returns the pair in initiator-order: the first is for the
		// message-reader to RECEIVE... see mapping below.
		result = &HandshakeResult{
			Send:       csSendMsg,
			Recv:       csRecvMsg,
			PeerNodeID: nid,
			PeerEd:     edPub,
			PeerStatic: hs.PeerStatic(),
			LocalIndex: localIndex,
			PeerIndex:  peerIndex,
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// asHandshake decodes a datagram as a handshake frame, or errors.
func asHandshake(b []byte) (handshakeFrame, error) {
	ft, err := frameType(b)
	if err != nil {
		return handshakeFrame{}, err
	}
	if ft != typeHandshake {
		return handshakeFrame{}, errType
	}
	return decodeHandshake(b)
}

// stopAndWait sends frame, then retransmits it on each RTO (exponential
// backoff, capped tries) until handle returns done=true or an error. Inbound
// datagrams are passed to handle; handle returning (false, nil) means "not what
// we're waiting for, keep retransmitting".
func stopAndWait(ctx context.Context, clk clock.Clock, snd Sender, inbox <-chan []byte,
	frame []byte, handle func([]byte) (bool, error)) error {

	if err := snd.Send(frame); err != nil {
		return err
	}
	rto := defaultRTO
	tries := 0
	timer := clk.NewTimer(rto)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case b := <-inbox:
			done, err := handle(b)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		case <-timer.C():
			tries++
			if tries >= maxTries {
				return errHandshakeTimeout
			}
			if err := snd.Send(frame); err != nil {
				return err
			}
			rto *= 2
			if rto > maxRTO {
				rto = maxRTO
			}
			timer.Reset(rto)
		}
	}
}

// awaitHandshake blocks for the first handshake frame matching pred (no
// retransmit on our side).
func awaitHandshake(ctx context.Context, clk clock.Clock, inbox <-chan []byte,
	pred func(handshakeFrame) bool) (handshakeFrame, error) {

	for {
		select {
		case <-ctx.Done():
			return handshakeFrame{}, ctx.Err()
		case b := <-inbox:
			hf, err := asHandshake(b)
			if err != nil {
				continue
			}
			if pred(hf) {
				return hf, nil
			}
		}
	}
}

var errHandshakeTimeout = errors.New("transport: handshake timed out")

// ErrHandshakeTimeout is returned when retransmits are exhausted.
func ErrHandshakeTimeout() error { return errHandshakeTimeout }
