// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"

	"golang.org/x/net/html"
)

func htmlEntityDecode(data string) (string, bool, error) {
	if strings.IndexByte(data, '&') < 0 {
		return data, false, nil
	}
	transformedData := html.UnescapeString(data)
	return transformedData, len(data) != len(transformedData), nil
}
