// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expstrs or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transformations

import (
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func utf8ToUnicode(str string) (string, bool, error) {
	for i := range len(str) {
		if str[i] >= utf8.RuneSelf {
			return doUTF8ToUnicode(str, i), true, nil
		}
	}
	return str, false, nil
}

func doUTF8ToUnicode(input string, pos int) string {
	resultCapacity := 0
	if _, size := utf8.DecodeRuneInString(input[pos:]); size == 1 {
		nonASCIIBytes := 0
		for index := pos; index < len(input); index++ {
			if input[index] >= utf8.RuneSelf {
				nonASCIIBytes++
			}
		}
		maxInt := int(^uint(0) >> 1)
		if nonASCIIBytes <= (maxInt-len(input))/5 {
			resultCapacity = len(input) + 5*nonASCIIBytes
		}
	}
	if resultCapacity == 0 {
		resultCapacity = pos
		for _, current := range input[pos:] {
			if current < utf8.RuneSelf {
				resultCapacity++
				continue
			}
			resultCapacity += unicodeEscapeLength(current)
		}
	}

	res := make([]byte, pos, resultCapacity)
	copy(res, input[0:pos])

	for _, current := range input[pos:] {
		if current < utf8.RuneSelf {
			res = append(res, byte(current))
			continue
		}
		res = appendUnicodeEscape(res, current)
	}

	return strings.WrapUnsafe(res)
}

func unicodeEscapeLength(current rune) int {
	switch {
	case current <= 0xffff:
		return 6
	case current <= 0xfffff:
		return 7
	default:
		return 8
	}
}

func appendUnicodeEscape(result []byte, current rune) []byte {
	const hexadecimal = "0123456789abcdef"
	digits := unicodeEscapeLength(current) - 2
	result = append(result, '%', 'u')
	for shift := (digits - 1) * 4; shift >= 0; shift -= 4 {
		result = append(result, hexadecimal[uint32(current)>>shift&0xf])
	}
	return result
}
