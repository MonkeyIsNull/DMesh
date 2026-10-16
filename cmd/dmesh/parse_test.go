package main

import (
	"flag"
	"reflect"
	"testing"
)

// TestParseInterspersed verifies that flags are parsed regardless of whether
// they appear before, after, or between positional arguments - the footgun
// where stdlib flag stops at the first non-flag, silently dropping any flag
// placed after the positionals.
func TestParseInterspersed(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantPos  []string
		wantBool bool
		wantStr  string
	}{
		{
			name:     "flags-before",
			args:     []string{"--no-mdns", "--peer", "boston", "nodeid", "file.bin"},
			wantPos:  []string{"nodeid", "file.bin"},
			wantBool: true,
			wantStr:  "boston",
		},
		{
			name:     "flags-after",
			args:     []string{"nodeid", "file.bin", "--no-mdns", "--peer", "boston"},
			wantPos:  []string{"nodeid", "file.bin"},
			wantBool: true,
			wantStr:  "boston",
		},
		{
			name:     "interleaved",
			args:     []string{"nodeid", "--peer", "boston", "file.bin", "--no-mdns"},
			wantPos:  []string{"nodeid", "file.bin"},
			wantBool: true,
			wantStr:  "boston",
		},
		{
			name:     "flags-only",
			args:     []string{"--no-mdns", "--peer", "boston"},
			wantPos:  nil,
			wantBool: true,
			wantStr:  "boston",
		},
		{
			name:     "missing-positional",
			args:     []string{"nodeid"},
			wantPos:  []string{"nodeid"},
			wantBool: false,
			wantStr:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			noMDNS := fs.Bool("no-mdns", false, "")
			peer := fs.String("peer", "", "")

			pos, err := parseInterspersed(fs, tc.args)
			if err != nil {
				t.Fatalf("parseInterspersed(%q) error: %v", tc.args, err)
			}
			if !reflect.DeepEqual(pos, tc.wantPos) {
				t.Errorf("positionals = %q, want %q", pos, tc.wantPos)
			}
			if *noMDNS != tc.wantBool {
				t.Errorf("--no-mdns = %v, want %v", *noMDNS, tc.wantBool)
			}
			if *peer != tc.wantStr {
				t.Errorf("--peer = %q, want %q", *peer, tc.wantStr)
			}
		})
	}
}
