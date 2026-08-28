// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !wasm

package operators

import (
	"fmt"

	re2 "github.com/wasilibs/go-re2"
	"github.com/wasilibs/go-re2/experimental"
)

type acceleratedRegexp interface {
	MatchString(string) bool
	FindStringSubmatchIndex(string) []int
}

func compileAcceleratedRegexp(expression string) (acceleratedRegexp, error) {
	return re2.Compile(expression)
}

func compileAcceleratedLatin1Regexp(expression string) (acceleratedRegexp, error) {
	if !isASCII(expression) {
		return nil, fmt.Errorf("latin-1 regexp acceleration requires an ASCII expression")
	}
	return experimental.CompileLatin1(expression)
}
