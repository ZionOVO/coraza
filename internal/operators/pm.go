// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.pm

package operators

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"unsafe"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs case-insensitive pattern matching using the Aho-Corasick algorithm for efficient
// multi-pattern searching. Matches space-separated keywords or patterns provided as arguments.
//
// Arguments:
// Space-separated keywords or patterns to match. Supports Snort data syntax like "A|42|C|44|F"
// for hex notation. All patterns are converted to lowercase for case-insensitive matching.
//
// Returns:
// true if any of the patterns are found in the input, false otherwise
//
// Example:
// ```seclang
// # Detect known malicious user agents
// SecRule REQUEST_HEADERS:User-Agent "@pm WebZIP WebCopier Webster" "id:170,deny,log"
//
// # Match multiple attack patterns
// SecRule ARGS "@pm <script> javascript: onerror=" "id:171,deny"
// ```
type pm struct {
	matcher      ahocorasick.AhoCorasick
	nonCapturing *indexedMatcher
	minLen       int
}

type pmCompiled struct {
	matcher      ahocorasick.AhoCorasick
	nonCapturing *indexedMatcher
}

var _ plugintypes.Operator = (*pm)(nil)

func newPM(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	data = strings.ToLower(data)
	dict := strings.Split(data, " ")
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	cacheKey := pmMemoizeKey("pm", "ascii-case-insensitive:leftmost-longest:dfa", dict)
	compiled, _ := memoizeDo(options.Memoizer, cacheKey, func() (any, error) {
		artifact := &pmCompiled{matcher: builder.Build(dict)}
		if !anyEmpty(dict) {
			artifact.nonCapturing = newIndexedMatcher(dict, true)
		}
		return artifact, nil
	})
	// TODO this operator is supposed to support snort data syntax: "@pm A|42|C|44|F"
	artifact := compiled.(*pmCompiled)
	return &pm{matcher: artifact.matcher, nonCapturing: artifact.nonCapturing, minLen: minPatternLen(dict)}, nil
}

func pmMemoizeKey(operator, buildOptions string, patterns []string) string {
	encoded := make([]byte, 0, len(patterns)*8)
	for _, pattern := range patterns {
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(len(pattern)))
		encoded = append(encoded, pattern...)
	}
	digest := sha256.Sum256(encoded)
	return operator + ":" + buildOptions + ":" + hex.EncodeToString(digest[:])
}

func (o *pm) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if len(value) < o.minLen {
		return false
	}
	if o.nonCapturing != nil {
		if !o.nonCapturing.matchWithState(tx, value) {
			return false
		}
		if !tx.Capturing() {
			return true
		}
	}
	return pmEvaluate(o.matcher, tx, value)
}

func minPatternLen(patterns []string) int {
	minimum := 0
	for _, pattern := range patterns {
		if len(pattern) == 0 {
			return 0
		}
		if minimum == 0 || len(pattern) < minimum {
			minimum = len(pattern)
		}
	}
	return minimum
}

func anyEmpty(values []string) bool {
	for _, value := range values {
		if value == "" {
			return true
		}
	}
	return false
}

func pmEvaluate(matcher ahocorasick.AhoCorasick, tx plugintypes.TransactionState, value string) bool {
	// Aho-Corasick stores the haystack in its iterator, so Iter converts the
	// complete string to a copied byte slice. The matcher never mutates the
	// haystack; a read-only view avoids copying large request bodies per rule.
	valueBytes := unsafe.Slice(unsafe.StringData(value), len(value))
	iter := matcher.IterByte(valueBytes)

	if !tx.Capturing() {
		// Not capturing so just one match is enough.
		return iter.Next() != nil
	}

	var numMatches int
	for {
		m := iter.Next()
		if m == nil {
			break
		}

		tx.CaptureField(numMatches, value[m.Start():m.End()])

		numMatches++
		if numMatches == 10 {
			return true
		}
	}

	return numMatches > 0
}

func init() {
	Register("pm", newPM)
}
