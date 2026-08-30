// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !wasm && !coraza.no_rx_acceleration && !coraza.disabled_operators.rx

package operators

import (
	"math/rand"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestAcceleratedRegexpMatchesGoRegexp(t *testing.T) {
	patterns := []string{
		`(?sm)som(.*)ta`,
		`(?sm)^hello.*world$`,
		`(?sm)(a)(b)?(c|d)`,
		`(?sm)(?:union\s+(?:all\s+)?select)`,
		`(?smi)(?:select|union|insert)`,
		`(?sm)[\r\n]\s*(?:content-type|set-cookie)\s*:`,
		`(?sm)(?:\.{2}[/\\]){2,}`,
		`(?sm)ハロー`,
		`(?sm)a(|b)`,
		`(?sm)(?P<name>[a-z]+)-([0-9]+)`,
		`(?sm)\Avalue\z`,
		`(?sm)[^0-9A-Z_a-z]+`,
		`(?sm)(x{2,8}?)(x*)`,
	}
	random := rand.New(rand.NewSource(1))
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			standard := regexp.MustCompile(pattern)
			accelerated, err := compileAcceleratedRegexp(pattern)
			if err != nil {
				t.Fatal(err)
			}
			for iteration := 0; iteration < 750; iteration++ {
				input := randomASCIIRegexpInput(random, 512+random.Intn(1537))
				if iteration%3 == 0 {
					seed := regexpMatchSeed(pattern)
					if isASCII(seed) {
						input += seed
					}
				}
				if have, want := accelerated.MatchString(input), standard.MatchString(input); have != want {
					t.Fatalf("MatchString mismatch for input %q: want %v, have %v", input, want, have)
				}
				have := capturedStrings(input, accelerated.FindStringSubmatchIndex(input))
				want := standard.FindStringSubmatch(input)
				if !slices.Equal(have, want) {
					t.Fatalf("submatch mismatch for input %q: want %v, have %v", input, want, have)
				}
			}
		})
	}
}

func TestRXAcceleratorIsOptInAndMalformedUTF8FallsBack(t *testing.T) {
	withoutOptIn, err := newRX(plugintypes.OperatorOptions{Arguments: `([^0-9A-Z_a-z]+)`})
	if err != nil {
		t.Fatal(err)
	}
	if withoutOptIn.(*rx).accelerated != nil {
		t.Fatal("accelerated regexp must require SecRxPreFilter On")
	}

	withOptIn, err := newRX(plugintypes.OperatorOptions{
		Arguments:          `([^0-9A-Z_a-z]+)`,
		RxPreFilterEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if withOptIn.(*rx).accelerated == nil {
		t.Fatal("expected accelerated regexp with SecRxPreFilter On")
	}

	waf := corazawaf.NewWAF()
	t.Cleanup(func() {
		if err := waf.Close(); err != nil {
			t.Error(err)
		}
	})
	input := "abc\x86" + strings.Repeat("Z", acceleratedRXMinInputBytes) + "-"
	tx := waf.NewTransaction()
	t.Cleanup(func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	})
	tx.Capture = true
	if !withOptIn.Evaluate(tx, input) {
		t.Fatal("expected malformed UTF-8 byte to match")
	}
	for index, want := range []string{"\x86", "\x86"} {
		have := tx.Variables().TX().Get(string(rune('0' + index)))
		if len(have) == 0 || have[0] != want {
			t.Fatalf("capture %d: want %q, have %q", index, want, have)
		}
	}
}

type testMemoizer struct {
	values map[string]any
}

func (memoizer *testMemoizer) Do(key string, compile func() (any, error)) (any, error) {
	if value, ok := memoizer.values[key]; ok {
		return value, nil
	}
	value, err := compile()
	if err == nil {
		memoizer.values[key] = value
	}
	return value, err
}

func FuzzAcceleratedRegexpMatchesGoRegexp(f *testing.F) {
	for _, seed := range []struct {
		pattern string
		input   string
	}{
		{pattern: `(?sm)(?:union\s+(?:all\s+)?select)`, input: " UNION ALL SELECT value"},
		{pattern: `(?smi)(select|union|insert)`, input: "routine text"},
		{pattern: `(?sm)(a)(b)?(c|d)`, input: "abcd"},
		{pattern: `(?sm)[^0-9A-Z_a-z]+`, input: "abc-123"},
	} {
		f.Add(seed.pattern, seed.input)
	}
	f.Fuzz(func(t *testing.T, pattern, input string) {
		if len(pattern) > 512 || len(input) > 64<<10 || !isASCII(input) {
			return
		}
		standard, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		accelerated, err := compileAcceleratedRegexp(pattern)
		if err != nil {
			return
		}
		if have, want := accelerated.MatchString(input), standard.MatchString(input); have != want {
			t.Fatalf("MatchString mismatch for pattern %q and input %q: want %v, have %v", pattern, input, want, have)
		}
		if have, want := capturedStrings(input, accelerated.FindStringSubmatchIndex(input)), standard.FindStringSubmatch(input); !slices.Equal(have, want) {
			t.Fatalf("submatch mismatch for pattern %q and input %q: want %v, have %v", pattern, input, want, have)
		}
	})
}

func capturedStrings(value string, indices []int) []string {
	if indices == nil {
		return nil
	}
	captures := make([]string, len(indices)/2)
	for index := range captures {
		start := indices[index*2]
		if start >= 0 {
			captures[index] = value[start:indices[index*2+1]]
		}
	}
	return captures
}

func randomASCIIRegexpInput(random *rand.Rand, size int) string {
	alphabet := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-/;<'\"() \t\r\n")
	data := make([]byte, size)
	for index := range data {
		data[index] = alphabet[random.Intn(len(alphabet))]
	}
	return string(data)
}

func regexpMatchSeed(pattern string) string {
	switch pattern {
	case `(?sm)som(.*)ta`:
		return "somedata"
	case `(?sm)^hello.*world$`:
		return "\nhello world"
	case `(?sm)(?:union\s+(?:all\s+)?select)`:
		return " union all select "
	case `(?smi)(?:select|union|insert)`:
		return " SELECT "
	case `(?sm)\Avalue\z`:
		return "value"
	default:
		return "abc-123xx"
	}
}
