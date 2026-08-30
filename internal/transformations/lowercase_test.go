// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"math/rand"
	"strings"
	"testing"
)

func TestLowerCase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "TestCase",
			want:  "testcase",
		},
		{
			input: "test\u0000case",
			want:  "test\u0000case",
		},
		{
			input: "testcase",
			want:  "testcase",
		},
		{
			input: "",
			want:  "",
		},
		{
			input: "ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY.",
			want:  "this is a text for testing lowercase functionality.",
		},
		{
			input: "ÜBER Σ",
			want:  "über σ",
		},
		{
			input: "\xffABC",
			want:  "�abc",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := lowerCase(tt.input)
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

func TestLowerCaseMatchesStandardLibrary(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	for iteration := 0; iteration < 100_000; iteration++ {
		input := make([]byte, random.Intn(257))
		if _, err := random.Read(input); err != nil {
			t.Fatal(err)
		}
		value := string(input)
		want := strings.ToLower(value)
		have, changed, err := lowerCase(value)
		if err != nil {
			t.Fatal(err)
		}
		if have != want || changed != (value != want) {
			t.Fatalf("lowerCase(%q) = (%q, %v), want (%q, %v)", value, have, changed, want, value != want)
		}
	}
}

func BenchmarkLowercase(b *testing.B) {
	tests := map[string]string{
		"short_mixed":        "tesTcase",
		"large_lower_ascii":  strings.Repeat("x", 64<<10),
		"large_mixed_ascii":  strings.Repeat("AbCdEfGh", 8<<10),
		"large_unicode":      strings.Repeat("ÜBER Σ ", 8<<10),
		"large_invalid_utf8": strings.Repeat("\x80\x81\xfe\xff", 16<<10),
	}
	for name, input := range tests {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for range b.N {
				if _, _, err := lowerCase(input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
