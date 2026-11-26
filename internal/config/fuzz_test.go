// SPDX-License-Identifier: EUPL-1.2

package config_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strings"
	"testing"

	"eid-tara-remote/internal/config"
)

// The fuzz tests cover the parsers that turn operator input into settings
// (CONTRIBUTING.md, Tests). Their seed corpora in testdata/fuzz run with the
// unit tests; go test -fuzz explores further.

// FuzzSplitList checks that an accepted list holds one trimmed, non-empty,
// distinct item per comma-separated part, and that a rejected list gets a
// fixed reason, which cannot echo it (PLAN.md §8).
func FuzzSplitList(f *testing.F) {
	const name = "RELAY_CLOUD_IDS"
	f.Fuzz(func(t *testing.T, s string) {
		items, err := config.SplitList(name, s)
		if err != nil {
			if msg := err.Error(); msg != name+": empty list item" && msg != name+": duplicate list item" {
				t.Fatalf("error = %q, want a fixed reason", msg)
			}
			return
		}
		if len(items) != strings.Count(s, ",")+1 {
			t.Fatalf("%d items from %d commas in %q", len(items), strings.Count(s, ","), s)
		}
		seen := make(map[string]bool, len(items))
		for _, item := range items {
			if item == "" || strings.Trim(item, " \t") != item || strings.Contains(item, ",") ||
				seen[item] || !strings.Contains(s, item) {
				t.Fatalf("item %q accepted from %q", item, s)
			}
			seen[item] = true
		}
	})
}

// parseCAsReasons are the fixed reasons of the CA bundle parser.
var parseCAsReasons = []string{
	"unexpected text outside the PEM blocks",
	"malformed PEM block",
	"PEM block is not a CERTIFICATE",
	"invalid certificate",
	"no PEM certificate",
}

// FuzzParseCAs checks that an accepted bundle holds certificate blocks only,
// none of them skipped, and that a rejected bundle gets a fixed reason
// (PLAN.md §8).
func FuzzParseCAs(f *testing.F) {
	// No certificate is committed as a seed (CONTRIBUTING.md, Tests); the
	// one generated for this run gives the fuzzer an accepted input.
	if p := generatedPEM(); p.err == nil {
		f.Add(p.cert)
		f.Add(slices.Concat(p.cert, []byte("\r\n"), p.cert))
		// Near misses: one byte of text after a block, and between two.
		f.Add(slices.Concat(p.cert, []byte("x")))
		f.Add(slices.Concat(p.cert, []byte("x\n"), p.cert))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pool, reason := config.ParseCAs(data)
		if reason != "" {
			if pool != nil || !slices.Contains(parseCAsReasons, reason) {
				t.Fatalf("reason %q with pool %v, want a fixed reason and no pool", reason, pool != nil)
			}
			return
		}
		if pool == nil || pool.Equal(x509.NewCertPool()) {
			t.Fatal("accepted without a certificate")
		}
		var blocks int
		rest := data
		for {
			// Only whitespace may lie before, between and after the blocks.
			rest = bytes.TrimLeft(rest, " \t\r\n")
			if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
				if len(rest) != 0 {
					t.Fatalf("accepted text outside the blocks: %.40q", rest)
				}
				break
			}
			var block *pem.Block
			if block, rest = pem.Decode(rest); block == nil {
				t.Fatal("accepted a BEGIN line without a block")
			}
			if _, err := x509.ParseCertificate(block.Bytes); block.Type != "CERTIFICATE" || err != nil {
				t.Fatalf("accepted a %q block that is not a valid certificate", block.Type)
			}
			blocks++
		}
		// pem.Decode skips a damaged block to reach the next one.
		if n := bytes.Count(data, []byte("-----BEGIN")); n != blocks {
			t.Fatalf("accepted %d BEGIN lines but %d blocks", n, blocks)
		}
	})
}

// FuzzUnknownNames checks that each unknown name Load reports, which the
// relay logs, is the fixed placeholder or the entry's own name in the shape
// of a setting name (PLAN.md §8, §10).
func FuzzUnknownNames(f *testing.F) {
	f.Fuzz(func(t *testing.T, entry string) {
		// The empty RELAY_APP_ID fails Load before it opens a file the entry
		// may name; only the reported names are under test.
		_, unknown, _ := config.Load([]string{"RELAY_APP_ID=", entry})
		for i, u := range unknown {
			if i > 0 && unknown[i-1] >= u {
				t.Fatalf("unknown = %q, want sorted without repeats", unknown)
			}
			if u == "RELAY_* (malformed name)" {
				continue
			}
			rest, ok := strings.CutPrefix(u, "RELAY_")
			if !ok || len(u) > 64 || !strings.HasPrefix(entry, u+"=") ||
				strings.Trim(rest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
				t.Fatalf("entry %q reported as %q", entry, u)
			}
		}
	})
}
