// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo || wasm

package operators

type acceleratedRegexp interface {
	MatchString(string) bool
	FindStringSubmatchIndex(string) []int
}

func compileAcceleratedRegexp(string) (acceleratedRegexp, error) {
	return nil, nil
}

func compileAcceleratedLatin1Regexp(string) (acceleratedRegexp, error) {
	return nil, nil
}
