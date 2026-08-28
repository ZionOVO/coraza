// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	stdstrings "strings"

	stringsutil "github.com/corazawaf/coraza/v3/internal/strings"
)

func urlDecodeUni(data string) (string, bool, error) {
	percent := stdstrings.IndexByte(data, '%')
	plus := stdstrings.IndexByte(data, '+')
	start := percent
	if start < 0 || plus >= 0 && plus < start {
		start = plus
	}
	if start >= 0 {
		bufferLength := unicodeDecodedBufferLength(data, start)
		buffer := make([]byte, bufferLength)
		copy(buffer[:start], data[:start])
		return inplaceUniDecode(data, buffer, start), true, nil
	}
	return data, false, nil
}

func unicodeDecodedBufferLength(input string, start int) int {
	reduction := 0
	for index := start; index+5 < len(input); index++ {
		if input[index] == '%' && (input[index+1] == 'u' || input[index+1] == 'U') &&
			stringsutil.ValidHex(input[index+2]) && stringsutil.ValidHex(input[index+3]) &&
			stringsutil.ValidHex(input[index+4]) && stringsutil.ValidHex(input[index+5]) {
			reduction += 5
			index += 5
		}
	}
	return len(input) - reduction
}

func inplaceUniDecode(input string, d []byte, pos int) string {
	inputLen := len(input)
	i := pos
	c := pos
	hmap := -1

	for i < inputLen {
		if input[i] == '%' {
			if (i+1 < inputLen) && ((input[i+1] == 'u') || (input[i+1] == 'U')) {
				/* Character is a percent sign. */
				/* IIS-specific %u encoding. */
				if i+5 < inputLen {
					/* We have at least 4 data bytes. */
					if (stringsutil.ValidHex(input[i+2])) && (stringsutil.ValidHex(input[i+3])) && (stringsutil.ValidHex(input[i+4])) && (stringsutil.ValidHex(input[i+5])) {
						/*
							TODO unicode mapping
							code = 0
							fact = 1
							for j = 5; j >= 2; j-- {
								if strings.ValidHex((input[i+j])) {
									if input[i+j] >= 97 {
										xv = (int(input[i+j]) - 97) + 10
									} else if input[i+j] >= 65 {
										xv = (int(input[i+j]) - 65) + 10
									} else {
										xv = int(input[i+j]) - 48
									}
									code += (xv * fact)
									fact *= 16
								}
							}
							if code >= 0 && code <= 65535 {
								t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
								result, _, _ := transform.String(t, string(code))
								hmap = result
							}*/

						if hmap != -1 {
							d[c] = byte(hmap)
						} else {
							/* We first make use of the lower byte here,
							 * ignoring the higher byte. */
							d[c] = stringsutil.X2c(input[i+4:])

							/* Full width ASCII (ff01 - ff5e)
							 * needs 0x20 added */
							if (d[c] > 0x00) && (d[c] < 0x5f) && ((input[i+2] == 'f') || (input[i+2] == 'F')) && ((input[i+3] == 'f') || (input[i+3] == 'F')) {
								d[c] += 0x20
							}
						}
						c++
						i += 6
					} else {
						/* Invalid data, skip %u. */
						d[c] = input[i]
						i++
						c++
						d[c] = input[i]
						c++
						i++
					}
				} else {
					/* Not enough bytes (4 data bytes), skip %u. */
					d[c] = input[i]
					i++
					c++
					d[c] = input[i]
					i++
					c++
				}
			} else {
				/* Standard URL encoding. */
				/* Are there enough bytes available? */
				if i+2 < inputLen {
					/* Yes. */

					/* Decode a %xx combo only if it is valid.
					 */
					c1 := input[i+1]
					c2 := input[i+2]

					if stringsutil.ValidHex(c1) && stringsutil.ValidHex(c2) {
						d[c] = stringsutil.X2c(input[i+1:])
						c++
						i += 3
					} else {
						/* Not a valid encoding, skip this % */
						d[c] = input[i]
						i++
						c++
					}
				} else {
					/* Not enough bytes available, skip this % */
					d[c] = input[i]
					i++
					c++
				}
			}
		} else {
			/* Character is not a percent sign. */
			if input[i] == '+' {
				d[c] = ' '
				c++
			} else {
				d[c] = input[i]
				c++
			}

			i++
		}
	}

	return stringsutil.WrapUnsafe(d[0:c])
}
