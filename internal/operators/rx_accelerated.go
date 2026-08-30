// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !wasm && !coraza.no_rx_acceleration

package operators

import (
	re2 "github.com/wasilibs/go-re2"
)

type acceleratedRegexp interface {
	MatchString(string) bool
	FindStringSubmatchIndex(string) []int
}

func compileAcceleratedRegexp(expression string) (acceleratedRegexp, error) {
	return re2.Compile(expression)
}
