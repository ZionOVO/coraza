// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"unicode"
	"unicode/utf8"

	stringsutil "github.com/corazawaf/coraza/v3/internal/strings"
)

func lowerCase(data string) (string, bool, error) {
	firstChange := -1
	for index := 0; index < len(data); {
		current := data[index]
		if current < utf8.RuneSelf {
			if current >= 'A' && current <= 'Z' {
				firstChange = index
				break
			}
			index++
			continue
		}
		decoded, size := utf8.DecodeRuneInString(data[index:])
		if size == 1 || unicode.ToLower(decoded) != decoded {
			firstChange = index
			break
		}
		index += size
	}
	if firstChange < 0 {
		return data, false, nil
	}

	resultCapacity := len(data)
	if data[firstChange] >= utf8.RuneSelf {
		_, size := utf8.DecodeRuneInString(data[firstChange:])
		remaining := len(data) - firstChange
		maxInt := int(^uint(0) >> 1)
		if size == 1 {
			switch {
			case utf8.ValidString(data[firstChange+1:]) && len(data) <= maxInt-2:
				resultCapacity = len(data) + 2
			case remaining <= (maxInt-firstChange)/3:
				resultCapacity = firstChange + 3*remaining
			}
		}
	}

	result := make([]byte, 0, resultCapacity)
	result = append(result, data[:firstChange]...)
	for index := firstChange; index < len(data); {
		current := data[index]
		if current < utf8.RuneSelf {
			if current >= 'A' && current <= 'Z' {
				current += 'a' - 'A'
			}
			result = append(result, current)
			index++
			continue
		}
		decoded, size := utf8.DecodeRuneInString(data[index:])
		if size == 1 {
			result = append(result, 0xef, 0xbf, 0xbd)
			index++
			continue
		}
		result = utf8.AppendRune(result, unicode.ToLower(decoded))
		index += size
	}
	return stringsutil.WrapUnsafe(result), true, nil
}
