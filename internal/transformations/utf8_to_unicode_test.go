// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUTF8ToUnicode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "hello world",
			want:  "hello world",
		},
		{
			input: "ハローワールド",
			want:  "%u30cf%u30ed%u30fc%u30ef%u30fc%u30eb%u30c9",
		},
		{
			input: "Hello ハローワールド world",
			want:  "Hello %u30cf%u30ed%u30fc%u30ef%u30fc%u30eb%u30c9 world",
		},
		{
			input: "ĤéllŌ wŏrld",
			want:  "%u0124%u00e9ll%u014c w%u014frld",
		},
		{
			input: "hello\000world",
			want:  "hello\000world",
		},
		{
			input: "hello 🍺",
			want:  "hello %u1f37a",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := utf8ToUnicode(tt.input)
			if err != nil {
				t.Error(err)
			}
			if tt.input == tt.want && changed || tt.input != tt.want && !changed {
				t.Errorf("input %q, have %q with changed %t", tt.input, have, changed)
			}
			if have != tt.want {
				t.Errorf("have %q, want %q", have, tt.want)
			}
		})
	}
}

func TestUTF8ToUnicodeMatchesEstablishedEncoding(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	for iteration := 0; iteration < 100_000; iteration++ {
		input := make([]byte, random.Intn(257))
		if _, err := random.Read(input); err != nil {
			t.Fatal(err)
		}
		value := string(input)
		want := referenceUTF8ToUnicode(value)
		have, _, err := utf8ToUnicode(value)
		if err != nil {
			t.Fatal(err)
		}
		if have != want {
			t.Fatalf("utf8ToUnicode(%q) = %q, want %q", value, have, want)
		}
	}
}

func referenceUTF8ToUnicode(input string) string {
	result := make([]byte, 0, len(input))
	for _, current := range input {
		if current < utf8.RuneSelf {
			result = append(result, byte(current))
			continue
		}
		digits := 1
		for remaining := current; remaining > 0xf; remaining >>= 4 {
			digits++
		}
		result = append(result, '%', 'u')
		for range 4 - digits {
			result = append(result, '0')
		}
		result = strconv.AppendUint(result, uint64(current), 16)
	}
	return string(result)
}

func BenchmarkUTF8ToUnicode(b *testing.B) {
	tests := map[string]string{
		"empty":              "",
		"ascii":              "hello world",
		"unicode":            "ハローワールド",
		"large_invalid_utf8": strings.Repeat("\x01\x02\x03\x04\x80\x81\xfe\xff", 8<<10),
	}

	for name, input := range tests {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for range b.N {
				if _, _, err := utf8ToUnicode(input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
