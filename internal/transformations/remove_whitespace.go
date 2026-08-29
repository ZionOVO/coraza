// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// removeWhitespace removes all whitespace characters from input.
func removeWhitespace(data string) (string, bool, error) {
	for i := 0; i < len(data); {
		current := data[i]
		if current >= utf8.RuneSelf {
			r, size := utf8.DecodeRuneInString(data[i:])
			if r == utf8.RuneError && size == 1 {
				return mapWithoutWhitespace(data)
			}
			if size > 1 && unicode.IsSpace(r) {
				return mapWithoutWhitespace(data)
			}
			i += size
			continue
		}
		switch current {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			return mapWithoutWhitespace(data)
		}
		i++
	}
	return data, false, nil
}

func mapWithoutWhitespace(data string) (string, bool, error) {
	changed := false
	transformedData := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			// if the character is a space, drop it
			changed = true
			return -1
		}
		// else keep it in the string
		return r
	}, data)

	return transformedData, changed, nil
}
