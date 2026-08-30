// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.rx

package operators

import (
	"math/rand"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/memoize"
	"rsc.io/binaryregexp"
)

func TestBinaryRXPrefilterMatchesBinaryRegexp(t *testing.T) {
	tests := []struct {
		name          string
		pattern       string
		wantPrefilter bool
		matching      []string
	}{
		{
			name:          "CRS 941310 alternatives",
			pattern:       `\x{bc}[^>\x{be}]*[>\x{be}]|<[^\x{be}]*\x{be}`,
			wantPrefilter: true,
			matching:      []string{"\xbctest>", "\xbctest\xbe", "<test\xbe"},
		},
		{
			name:          "literal binary prefix",
			pattern:       `\xac\xed\x00\x05`,
			wantPrefilter: true,
			matching:      []string{"\xac\xed\x00\x05", "prefix\xac\xed\x00\x05suffix"},
		},
		{
			name:          "required literals across concatenation",
			pattern:       `\xff(?:foo)?bar\xfe`,
			wantPrefilter: true,
			matching:      []string{"\xffbar\xfe", "\xfffffoobar\xfesuffix"},
		},
		{
			name:          "case folded binary pattern",
			pattern:       `(?i)\xffheader:`,
			wantPrefilter: true,
			matching:      []string{"\xffHEADER:", "prefix\xffHeader:suffix"},
		},
		{
			name:          "unconstrained alternative",
			pattern:       `\xfffoo|.*`,
			wantPrefilter: false,
			matching:      []string{"", "ordinary text", "\xfffoo"},
		},
		{
			name:          "binary character class only",
			pattern:       `[\x80-\xff]+`,
			wantPrefilter: false,
			matching:      []string{"\x80", "\xff\xfe"},
		},
	}

	random := rand.New(rand.NewSource(1))
	waf := corazawaf.NewWAF()
	t.Cleanup(func() {
		if err := waf.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reference := binaryregexp.MustCompile(tc.pattern)
			op, err := newRX(plugintypes.OperatorOptions{
				Arguments:          tc.pattern,
				RxPreFilterEnabled: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			binaryOperator, ok := op.(*binaryRX)
			if !ok {
				t.Fatalf("expected binaryRX, got %T", op)
			}
			if have := binaryOperator.prefilter != nil; have != tc.wantPrefilter {
				t.Fatalf("prefilter availability: want %v, have %v", tc.wantPrefilter, have)
			}

			inputs := append([]string(nil), tc.matching...)
			inputs = append(inputs, "", "ordinary request body", string(make([]byte, 1024)))
			for range 5_000 {
				value := make([]byte, random.Intn(1025))
				if _, err := random.Read(value); err != nil {
					t.Fatal(err)
				}
				inputs = append(inputs, string(value))
			}

			tx := waf.NewTransaction()
			defer func() {
				if err := tx.Close(); err != nil {
					t.Error(err)
				}
			}()
			for _, input := range inputs {
				want := reference.MatchString(input)
				if have := op.Evaluate(tx, input); have != want {
					t.Fatalf("pattern %q input %x: want %v, have %v", tc.pattern, []byte(input), want, have)
				}
			}
		})
	}
}

func FuzzBinaryRXPrefilterNoFalseNegatives(f *testing.F) {
	for _, seed := range []struct {
		pattern string
		input   []byte
	}{
		{pattern: `\x{bc}[^>\x{be}]*[>\x{be}]|<[^\x{be}]*\x{be}`, input: []byte("\xbctest>")},
		{pattern: `\xac\xed\x00\x05`, input: []byte("prefix\xac\xed\x00\x05suffix")},
		{pattern: `\xff(?:foo)?bar\xfe`, input: []byte("\xfffffoobar\xfe")},
		{pattern: `(?i)\xffheader:`, input: []byte("\xffHEADER:")},
	} {
		f.Add(seed.pattern, seed.input)
	}

	f.Fuzz(func(t *testing.T, pattern string, input []byte) {
		if len(pattern) > 256 || len(input) > 512 {
			return
		}
		reference, err := binaryregexp.Compile(pattern)
		if err != nil {
			return
		}
		filter := compileBinaryRequiredPrefilter(pattern)
		value := string(input)
		if filter != nil && reference.MatchString(value) && !filter.possible(nil, value) {
			t.Fatalf("binary prefilter rejected match for pattern %q and input %x", pattern, input)
		}
	})
}

func TestBinaryRXPrefilterMemoizationSeparatesConfiguration(t *testing.T) {
	const ownerID = 987654321
	cache := memoize.NewMemoizer(ownerID)
	t.Cleanup(func() {
		memoize.Release(ownerID)
	})
	options := plugintypes.OperatorOptions{
		Arguments: `\xffrequired`,
		Memoizer:  cache,
	}
	disabledOperator, err := newBinaryRX(options)
	if err != nil {
		t.Fatal(err)
	}
	options.RxPreFilterEnabled = true
	enabledOperator, err := newBinaryRX(options)
	if err != nil {
		t.Fatal(err)
	}
	if disabledOperator.(*binaryRX).prefilter != nil {
		t.Fatal("disabled operator unexpectedly received a prefilter")
	}
	if enabledOperator.(*binaryRX).prefilter == nil {
		t.Fatal("enabled operator did not receive a prefilter")
	}
}

func TestBinaryRXPrefilterPreservesCaptures(t *testing.T) {
	op, err := newBinaryRX(plugintypes.OperatorOptions{
		Arguments:          `(\xfffoo)(bar)?`,
		RxPreFilterEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	waf := corazawaf.NewWAF()
	t.Cleanup(func() {
		if err := waf.Close(); err != nil {
			t.Error(err)
		}
	})
	tx := waf.NewTransaction()
	t.Cleanup(func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	})
	tx.Capture = true
	if !op.Evaluate(tx, "prefix\xfffoobarsuffix") {
		t.Fatal("expected binary regexp to match")
	}
	for index, want := range []string{"\xfffoobar", "\xfffoo", "bar"} {
		have := tx.Variables().TX().Get(string(rune('0' + index)))
		if len(have) == 0 || have[0] != want {
			t.Fatalf("capture %d: want %q, have %q", index, want, have)
		}
	}
}
