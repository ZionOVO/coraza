// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !wasm

package operators

import (
	"math/rand"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"rsc.io/binaryregexp"
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
		`(?smi)select`,
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
				input := randomValidRegexpInput(random, 512+random.Intn(1537))
				if iteration%3 == 0 {
					input += regexpMatchSeed(pattern)
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

func TestAcceleratedLatin1RegexpMatchesBinaryRegexp(t *testing.T) {
	patterns := []string{
		`\xac\xed\x00\x05`,
		`\x{bc}[^>\x{be}]*[>\x{be}]`,
		`([\x80-\xff]+)(test)?`,
		`^\xff.*\x80$`,
		`(?:\x00|\xfe|plain)+`,
		`()*`,
	}
	random := rand.New(rand.NewSource(2))
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			standard, err := binaryregexp.Compile(pattern)
			if err != nil {
				t.Fatal(err)
			}
			accelerated, err := compileAcceleratedLatin1Regexp(pattern)
			if err != nil {
				t.Fatal(err)
			}
			for iteration := 0; iteration < 750; iteration++ {
				data := make([]byte, 512+random.Intn(1537))
				if _, err := random.Read(data); err != nil {
					t.Fatal(err)
				}
				if iteration%3 == 0 {
					data = append(data, 0xac, 0xed, 0x00, 0x05)
				}
				input := string(data)
				if have, want := accelerated.MatchString(input), standard.MatchString(input); have != want {
					t.Fatalf("MatchString mismatch for input %x: want %v, have %v", data, want, have)
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

	input := "abc\x86" + strings.Repeat("Z", acceleratedRXMinInputBytes) + "-"
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
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

	binaryWithUnicodeExpression, err := newBinaryRX(plugintypes.OperatorOptions{
		Arguments:          "ٕ",
		RxPreFilterEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if binaryWithUnicodeExpression.(*binaryRX).accelerated != nil {
		t.Fatal("binary regexp with a non-ASCII expression must use the established backend")
	}

	binaryWithAmbiguousCapture, err := newBinaryRX(plugintypes.OperatorOptions{
		Arguments:          `(|0)*`,
		RxPreFilterEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	binaryInput := "0" + strings.Repeat("x", acceleratedRXMinInputBytes)
	binaryTX := waf.NewTransaction()
	binaryTX.Capture = true
	if !binaryWithAmbiguousCapture.Evaluate(binaryTX, binaryInput) {
		t.Fatal("expected binary regexp to match")
	}
	for index, want := range []string{"0", "0"} {
		have := binaryTX.Variables().TX().Get(string(rune('0' + index)))
		if len(have) == 0 || have[0] != want {
			t.Fatalf("binary capture %d: want %q, have %q", index, want, have)
		}
	}
}

func TestBinaryRXMemoizationSeparatesOptInState(t *testing.T) {
	memoizer := &testMemoizer{values: map[string]any{}}
	withAcceleration, err := newBinaryRX(plugintypes.OperatorOptions{
		Arguments:          `\xff`,
		Memoizer:           memoizer,
		RxPreFilterEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	withoutAcceleration, err := newBinaryRX(plugintypes.OperatorOptions{
		Arguments:          `\xff`,
		Memoizer:           memoizer,
		RxPreFilterEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if withAcceleration.(*binaryRX).accelerated == nil {
		t.Fatal("expected opted-in binary expression to use acceleration")
	}
	if withoutAcceleration.(*binaryRX).accelerated != nil {
		t.Fatal("binary expression without opt-in reused an accelerated artifact")
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

func FuzzAcceleratedLatin1RegexpMatchesBinaryRegexp(f *testing.F) {
	for _, seed := range []struct {
		pattern string
		input   []byte
	}{
		{pattern: `\xac\xed\x00\x05`, input: []byte{0xac, 0xed, 0x00, 0x05}},
		{pattern: `([\x80-\xff]+)(test)?`, input: []byte{0xff, 0x80, 't', 'e', 's', 't'}},
		{pattern: `(?:\x00|\xfe|plain)+`, input: []byte{0, 0xfe}},
	} {
		f.Add(seed.pattern, seed.input)
	}
	f.Fuzz(func(t *testing.T, pattern string, input []byte) {
		if len(pattern) > 512 || len(input) > 64<<10 {
			return
		}
		standard, err := binaryregexp.Compile(pattern)
		if err != nil {
			return
		}
		accelerated, err := compileAcceleratedLatin1Regexp(pattern)
		if err != nil {
			return
		}
		value := string(input)
		if have, want := accelerated.MatchString(value), standard.MatchString(value); have != want {
			t.Fatalf("MatchString mismatch for pattern %q and input %x: want %v, have %v", pattern, input, want, have)
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

func randomValidRegexpInput(random *rand.Rand, size int) string {
	alphabet := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-/;<'\"() \t\r\néſKΣςハロー")
	var data strings.Builder
	data.Grow(size)
	for data.Len() < size {
		data.WriteRune(alphabet[random.Intn(len(alphabet))])
	}
	return data.String()
}

func regexpMatchSeed(pattern string) string {
	switch pattern {
	case `(?sm)som(.*)ta`:
		return "somedata"
	case `(?sm)^hello.*world$`:
		return "\nhello world"
	case `(?sm)(?:union\s+(?:all\s+)?select)`:
		return " union all select "
	case `(?smi)(?:select|union|insert)`, `(?smi)select`:
		return " SELECT "
	case `(?sm)ハロー`:
		return "ハロー"
	case `(?sm)\Avalue\z`:
		return "value"
	default:
		return "abc-123xx"
	}
}
