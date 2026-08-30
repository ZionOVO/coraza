// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.rx

package operators

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestRequiredByteMatcherNeverRejectsCandidateLiterals(t *testing.T) {
	needles := []string{"union", "select", "javascript", "onerror", "document.cookie"}
	for _, caseFold := range []bool{false, true} {
		matcher := newRequiredByteMatcher(needles, caseFold)
		for _, needle := range needles {
			value := "prefix_" + needle + "_suffix"
			if caseFold {
				value = strings.ToUpper(value)
			}
			if !matcher.match(value) {
				t.Fatalf("required-byte matcher rejected %q with caseFold=%v", needle, caseFold)
			}
		}
	}
}

func TestRequiredByteMatcherReusesTransactionBytePresence(t *testing.T) {
	waf := corazawaf.NewWAF()
	t.Cleanup(func() {
		if err := waf.Close(); err != nil {
			t.Error(err)
		}
	})
	tx := waf.NewTransaction()
	t.Cleanup(func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	})

	value := strings.Repeat("x", cachedBytePresenceMinInputBytes*2)
	negative := &requiredByteMatcher{ascii: true, characters: "z"}
	negative.add('z', false)
	if negative.matchWithState(tx, value) {
		t.Fatal("unexpected required-byte match")
	}
	if _, found := tx.LoadBytePresence(value); !found {
		t.Fatal("complete negative scan did not populate transaction cache")
	}

	positive := &requiredByteMatcher{ascii: true, characters: "x"}
	positive.add('x', false)
	if !positive.matchWithState(tx, value) {
		t.Fatal("cached byte presence rejected an existing byte")
	}
}

func TestExactMatchOptimizationPreservesCaptures(t *testing.T) {
	operator, err := newRX(plugintypes.OperatorOptions{
		Arguments:          `^Upload$`,
		RxPreFilterEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	waf := corazawaf.NewWAF()
	t.Cleanup(func() {
		if err := waf.Close(); err != nil {
			t.Error(err)
		}
	})
	tx := waf.NewTransaction()
	t.Cleanup(func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	})
	tx.Capture = true
	if !operator.Evaluate(tx, "Upload") {
		t.Fatal("exact expression did not match")
	}
	captured := tx.Variables().TX().Get("0")
	if len(captured) != 1 || captured[0] != "Upload" {
		t.Fatalf("full-match capture is absent: %v", captured)
	}
}

func TestUnicodeFoldedLiteralsBypassBytePrefilter(t *testing.T) {
	for _, pattern := range []string{`(?i)é`, `(?i)Σ`} {
		filter := compilePrefilter(pattern)
		if filter.match != nil || filter.matchWithState != nil {
			t.Errorf("Unicode-folded pattern %q must use the regular-expression backend", pattern)
		}
	}
}
