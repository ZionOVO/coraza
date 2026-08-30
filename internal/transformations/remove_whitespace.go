// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"unicode"
	"unicode/utf8"

	stringsutil "github.com/corazawaf/coraza/v3/internal/strings"
)

// removeWhitespace removes all whitespace characters from input.
func removeWhitespace(data string) (string, bool, error) {
	for i := 0; i < len(data); {
		current := data[i]
		if current >= utf8.RuneSelf {
			r, size := utf8.DecodeRuneInString(data[i:])
			if r == utf8.RuneError && size == 1 {
				return mapWithoutWhitespace(data, i)
			}
			if size > 1 && unicode.IsSpace(r) {
				return mapWithoutWhitespace(data, i)
			}
			i += size
			continue
		}
		switch current {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			return mapWithoutWhitespace(data, i)
		}
		i++
	}
	return data, false, nil
}

func mapWithoutWhitespace(data string, start int) (string, bool, error) {
	outputSize, changed := whitespaceMappedSize(data, start)
	transformedData := make([]byte, 0, outputSize)
	transformedData = append(transformedData, data[:start]...)
	for index := start; index < len(data); {
		current := data[index]
		if current < utf8.RuneSelf {
			switch current {
			case ' ', '\t', '\n', '\r', '\v', '\f':
			default:
				transformedData = append(transformedData, current)
			}
			index++
			continue
		}

		r, size := utf8.DecodeRuneInString(data[index:])
		if r == utf8.RuneError && size == 1 {
			transformedData = append(transformedData, '\xef', '\xbf', '\xbd')
			index++
			continue
		}
		if unicode.IsSpace(r) {
		} else {
			transformedData = append(transformedData, data[index:index+size]...)
		}
		index += size
	}

	return stringsutil.WrapUnsafe(transformedData), changed, nil
}

func whitespaceMappedSize(data string, start int) (int, bool) {
	outputSize := start
	changed := false
	for index := start; index < len(data); {
		current := data[index]
		if current < utf8.RuneSelf {
			switch current {
			case ' ', '\t', '\n', '\r', '\v', '\f':
				changed = true
			default:
				outputSize++
			}
			index++
			continue
		}
		r, size := utf8.DecodeRuneInString(data[index:])
		if r == utf8.RuneError && size == 1 {
			outputSize += utf8.RuneLen(utf8.RuneError)
			index++
			continue
		}
		if unicode.IsSpace(r) {
			changed = true
		} else {
			outputSize += size
		}
		index += size
	}
	return outputSize, changed
}
