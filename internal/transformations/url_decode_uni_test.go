// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	stringsutil "github.com/corazawaf/coraza/v3/internal/strings"
)

func TestURLDecodeUniMatchesEstablishedDecoding(t *testing.T) {
	inputs := []string{"", "%", "%u", "%u1", "%u12", "%u123", "%u1234", "%Uffff", "%uff01", "%uff5e", "%uxxxx", "%41", "%4G", "+", "a%u1234b%20c+d"}
	random := rand.New(rand.NewSource(1))
	for range 100_000 {
		value := make([]byte, random.Intn(257))
		if _, err := random.Read(value); err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, string(value))
	}
	for _, input := range inputs {
		want := referenceURLDecodeUni(input)
		have, _, err := urlDecodeUni(input)
		if err != nil {
			t.Fatal(err)
		}
		if have != want {
			t.Fatalf("urlDecodeUni(%q) = %q, want %q", input, have, want)
		}
	}
}

func referenceURLDecodeUni(input string) string {
	result := make([]byte, 0, len(input))
	for index := 0; index < len(input); {
		if input[index] == '%' {
			if index+1 < len(input) && (input[index+1] == 'u' || input[index+1] == 'U') {
				if index+5 < len(input) && stringsutil.ValidHex(input[index+2]) && stringsutil.ValidHex(input[index+3]) && stringsutil.ValidHex(input[index+4]) && stringsutil.ValidHex(input[index+5]) {
					decoded := stringsutil.X2c(input[index+4:])
					if decoded > 0 && decoded < 0x5f && (input[index+2] == 'f' || input[index+2] == 'F') && (input[index+3] == 'f' || input[index+3] == 'F') {
						decoded += 0x20
					}
					result = append(result, decoded)
					index += 6
					continue
				}
				result = append(result, input[index], input[index+1])
				index += 2
				continue
			}
			if index+2 < len(input) && stringsutil.ValidHex(input[index+1]) && stringsutil.ValidHex(input[index+2]) {
				result = append(result, stringsutil.X2c(input[index+1:]))
				index += 3
				continue
			}
		}
		if input[index] == '+' {
			result = append(result, ' ')
		} else {
			result = append(result, input[index])
		}
		index++
	}
	return string(result)
}

func BenchmarkURLDecode(b *testing.B) {
	tests := map[string]string{
		"empty":                 "",
		"plain":                 "helloworld",
		"plus":                  "hello+world",
		"encoded":               "%E3%83%8F%E3%83%AD%E3%83%BC%E3%83%AF%E3%83%BC%E3%83%AB%E3%83%89",
		"large_unicode_escapes": strings.Repeat("\x01\x02\x03\x04%ufffd%ufffd%ufffd%ufffd", 8<<10),
	}

	for _, mode := range []string{"normal", "unicode"} {
		f := urlDecode
		if mode == "unicode" {
			f = urlDecodeUni
		}
		for name, input := range tests {
			b.Run(fmt.Sprintf("%s/%s", mode, name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for range b.N {
					if _, _, err := f(input); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
