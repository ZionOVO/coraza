// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.no_memoize && !tinygo

package memoize

import "testing"

func TestReleaseDoesNotDeleteConcurrentReplacement(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	const key = "replaced"
	old := &entry{value: "old", owners: map[uint64]struct{}{1: {}}}
	replacement := &entry{value: "replacement", owners: map[uint64]struct{}{2: {}}}
	cache.Store(key, old)
	cache.Store(key, replacement)

	releaseEntry(key, old, 1)

	value, ok := cache.Load(key)
	if !ok || value != replacement {
		t.Fatal("releasing a stale entry deleted its concurrent replacement")
	}
}
