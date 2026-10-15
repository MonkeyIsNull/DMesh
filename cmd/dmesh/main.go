// Command dmesh is the DMesh v0.1 node and control CLI.
//
//	dmesh id                      print this node's ID (generating on first run)
//	dmesh up [flags]              run the node: discover, connect, status view
//	dmesh network-key gen|set|show|clear
//	dmesh trust <id> [label] | trust list | untrust <id>
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/MonkeyIsNull/DMesh/internal/clock"
	"github.com/MonkeyIsNull/DMesh/internal/config"
	"github.com/MonkeyIsNull/DMesh/internal/discovery"
	"github.com/MonkeyIsNull/DMesh/internal/identity"
	"github.com/MonkeyIsNull/DMesh/internal/node"
	"github.com/MonkeyIsNull/DMesh/internal/transport"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "id":
		err = cmdID(os.Args[2:])
	case "up":
		err = cmdUp(os.Args[2:])
	case "network-key":
		err = cmdNetworkKey(os.Args[2:])
	case "trust":
		err = cmdTrust(os.Args[2:])
	case "untrust":
		err = cmdUntrust(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "dmesh: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dmesh:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dmesh - a serverless mesh where your sessions don't die (v0.1)

usage:
  dmesh id
  dmesh up [--label NAME] [--port N] [--no-mdns] [--trust-only]
  dmesh network-key gen|set|show|clear
  dmesh trust <node-id> [label]
  dmesh trust list
  dmesh untrust <node-id>
`)
}

func openConfig() (*config.Config, error) { return config.Open() }

// cmdID prints this node's identity, generating it on first run.
func cmdID(args []string) error {
	fs := flag.NewFlagSet("id", flag.ExitOnError)
	label := fs.String("label", "", "optional human label to set on first run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := openConfig()
	if err != nil {
		return err
	}
	id, created, err := c.LoadIdentity(*label)
	if err != nil {
		return err
	}
	nid := id.NodeID()
	if created {
		fmt.Printf("generated new identity\n")
	}
	fmt.Printf("node id:  %s\n", nid.String())
	fmt.Printf("short:    %s\n", nid.Short())
	fmt.Printf("label:    %s\n", orNone(id.Label))
	fmt.Printf("key file: %s\n", c.IdentityPath())
	return nil
}

// cmdUp runs the node.
func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	label := fs.String("label", "", "human label for this node")
	port := fs.Int("port", 0, "UDP port to listen on (0 = ephemeral)")
	noMDNS := fs.Bool("no-mdns", false, "disable mDNS discovery")
	trustOnly := fs.Bool("trust-only", false, "accept only allow-listed peers (no trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := openConfig()
	if err != nil {
		return err
	}
	id, _, err := c.LoadIdentity(*label)
	if err != nil {
		return err
	}
	if *label != "" && id.Label != *label {
		id.Label = *label
		if serr := id.Save(c.IdentityPath()); serr != nil {
			return serr
		}
	}

	// Fail closed: a network key is mandatory; there is NO keyless fallback.
	psk, err := c.LoadNetworkKey()
	if err != nil {
		return err
	}
	if len(psk) == 0 {
		return errors.New("no network key configured; run 'dmesh network-key gen' and share it (fail closed)")
	}

	// Build the trust policy from the allow-list against authenticated IDs.
	trusted, err := loadTrustedSet(c)
	if err != nil {
		return err
	}
	policy := transport.AllowList(trusted, *trustOnly)
	enforce := *trustOnly || len(trusted) > 0

	conn, err := transport.ListenUDP(*port)
	if err != nil {
		return err
	}
	defer conn.Close()

	var disc discovery.Discovery
	if !*noMDNS {
		disc = discovery.NewMDNS()
		defer disc.Close()
	}

	n, err := node.New(node.Config{
		Identity:         id,
		NetworkPSK:       psk,
		Policy:           policy,
		Discovery:        disc,
		Conn:             conn,
		Clock:            clock.Real{},
		EnforceAllowList: enforce,
		SendGreeting:     true,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- n.Run(ctx) }()

	printHeader(n, psk)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			<-errCh
			fmt.Println("\nshutting down.")
			return nil
		case err := <-errCh:
			return err
		case <-ticker.C:
			renderStatus(n)
		}
	}
}

func printHeader(n *node.Node, psk []byte) {
	fmt.Printf("DMesh node up.\n")
	fmt.Printf("  id:      %s (%s)\n", n.SelfID().Short(), orNone(n.SelfLabel()))
	fmt.Printf("  listen:  %s\n", n.LocalAddr())
	fmt.Printf("  network: %s\n", config.Fingerprint(psk))
	if n.EnforceAllowList() {
		fmt.Printf("  trust:   allow-list ENFORCED (only trusted peers admitted)\n")
	} else {
		fmt.Printf("  trust:   trust-on-first-use (anyone with the network key)\n")
	}
	fmt.Printf("  (Ctrl-C to quit)\n\n")
}

// renderStatus redraws the peer table.
func renderStatus(n *node.Node) {
	peers := n.Snapshot()
	sort.Slice(peers, func(i, j int) bool { return peers[i].Endpoint.String() < peers[j].Endpoint.String() })

	var b strings.Builder
	fmt.Fprintf(&b, "\033[H\033[2J") // clear screen + home
	fmt.Fprintf(&b, "DMesh %s (%s)   peers: %d\n\n", n.SelfID().Short(), orNone(n.SelfLabel()), len(peers))
	fmt.Fprintf(&b, "%-12s  %-16s  %-22s  %-12s  %s\n", "ID", "LABEL", "ENDPOINT", "STATE", "LAST-SEEN")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 78))
	now := time.Now()
	for _, p := range peers {
		idCol := "(unknown)"
		if p.HasID {
			idCol = p.NodeID.Short()
		}
		last := "-"
		if !p.LastSeen.IsZero() {
			last = fmt.Sprintf("%ds ago", int(now.Sub(p.LastSeen).Seconds()))
		}
		fmt.Fprintf(&b, "%-12s  %-16s  %-22s  %-12s  %s\n",
			idCol, truncate(p.Label, 16), p.Endpoint.String(), p.State.String(), last)
	}
	fmt.Print(b.String())
}

// cmdNetworkKey manages the pre-shared network key.
func cmdNetworkKey(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: dmesh network-key gen|set|show|clear")
	}
	c, err := openConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "gen":
		key := make([]byte, config.NetworkKeyLen)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		if err := c.SaveNetworkKey(key); err != nil {
			return err
		}
		fmt.Printf("generated and stored a new 32-byte network key.\n")
		fmt.Printf("share this with peers (out of band), then run 'dmesh up':\n\n")
		fmt.Printf("  %s\n\n", base64.StdEncoding.EncodeToString(key))
		fmt.Printf("fingerprint: %s\n", config.Fingerprint(key))
		return nil
	case "set":
		var s string
		if len(args) >= 2 {
			s = args[1]
		} else {
			data, _ := io.ReadAll(bufio.NewReader(os.Stdin))
			s = strings.TrimSpace(string(data))
		}
		if envv := strings.TrimSpace(os.Getenv(config.EnvNetworkKey)); s == "" && envv != "" {
			s = envv
		}
		raw, derr := base64.StdEncoding.DecodeString(s)
		if derr != nil {
			return fmt.Errorf("network key must be base64: %w", derr)
		}
		if err := c.SaveNetworkKey(raw); err != nil {
			return err
		}
		fmt.Printf("stored network key (fingerprint %s)\n", config.Fingerprint(raw))
		return nil
	case "show":
		key, err := c.LoadNetworkKey()
		if err != nil {
			return err
		}
		fmt.Printf("network key fingerprint: %s\n", config.Fingerprint(key))
		return nil
	case "clear":
		if err := c.ClearNetworkKey(); err != nil {
			return err
		}
		fmt.Println("network key cleared.")
		return nil
	default:
		return fmt.Errorf("unknown network-key subcommand %q", args[0])
	}
}

// cmdTrust manages the allow-list.
func cmdTrust(args []string) error {
	c, err := openConfig()
	if err != nil {
		return err
	}
	if len(args) >= 1 && args[0] == "list" {
		tl, lerr := c.LoadTrust()
		if lerr != nil {
			return lerr
		}
		if len(tl.Entries) == 0 {
			fmt.Println("trust list is empty (trust-on-first-use: anyone with the network key).")
			return nil
		}
		for _, e := range tl.Entries {
			nid, _ := identity.ParseNodeID(e.NodeID)
			fmt.Printf("%s  %s\n", nid.Short(), orNone(e.Label))
		}
		return nil
	}
	if len(args) < 1 {
		return errors.New("usage: dmesh trust <node-id> [label] | dmesh trust list")
	}
	label := ""
	if len(args) >= 2 {
		label = args[1]
	}
	if err := c.Trust(args[0], label); err != nil {
		return err
	}
	fmt.Printf("trusted %s\n", args[0])
	return nil
}

func cmdUntrust(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: dmesh untrust <node-id>")
	}
	c, err := openConfig()
	if err != nil {
		return err
	}
	if err := c.Untrust(args[0]); err != nil {
		return err
	}
	fmt.Printf("untrusted %s\n", args[0])
	return nil
}

func loadTrustedSet(c *config.Config) (map[identity.NodeID]struct{}, error) {
	tl, err := c.LoadTrust()
	if err != nil {
		return nil, err
	}
	set := make(map[identity.NodeID]struct{}, len(tl.Entries))
	for _, e := range tl.Entries {
		nid, perr := identity.ParseNodeID(e.NodeID)
		if perr != nil {
			continue
		}
		set[nid] = struct{}{}
	}
	return set, nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
