// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"math/rand"
	"strings"
	"testing"
	"unicode"
)

func TestRemoveWhiteSpace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "test",
			want:  "test",
		},
		{
			input: "t e s t",
			want:  "test",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := removeWhitespace(tt.input)
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

func TestRemoveWhitespaceMatchesStringsMapForArbitraryBytes(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	inputs := [][]byte{{0xff, 'A', 'B', 'C'}}
	for range 5_000 {
		data := make([]byte, random.Intn(257))
		if _, err := random.Read(data); err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, data)
	}

	for _, input := range inputs {
		value := string(input)
		want, wantChanged := removeWhitespaceReference(value)
		have, haveChanged, err := removeWhitespace(value)
		if err != nil {
			t.Fatal(err)
		}
		if have != want || haveChanged != wantChanged {
			t.Fatalf("input %x: want %x changed=%t, have %x changed=%t", input, []byte(want), wantChanged, []byte(have), haveChanged)
		}
	}
}

func removeWhitespaceReference(data string) (string, bool) {
	changed := false
	transformed := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			changed = true
			return -1
		}
		return r
	}, data)
	return transformed, changed
}
