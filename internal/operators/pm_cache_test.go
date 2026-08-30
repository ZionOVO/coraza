// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestPMFromDatasetCacheUsesDatasetContents(t *testing.T) {
	memoizer := &operatorTestMemoizer{values: map[string]any{}}
	first, err := newPMFromDataset(plugintypes.OperatorOptions{
		Arguments: "blocked",
		Datasets:  map[string][]string{"blocked": {"alpha"}},
		Memoizer:  memoizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := newPMFromDataset(plugintypes.OperatorOptions{
		Arguments: "blocked",
		Datasets:  map[string][]string{"blocked": {"beta"}},
		Memoizer:  memoizer,
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
	if !first.Evaluate(tx, "alpha") || first.Evaluate(tx, "beta") {
		t.Fatal("first operator did not use its dataset")
	}
	if !second.Evaluate(tx, "beta") || second.Evaluate(tx, "alpha") {
		t.Fatal("second operator reused a same-named dataset with different contents")
	}
}

func TestPMFromDatasetCacheCannotCollideWithRegex(t *testing.T) {
	memoizer := &operatorTestMemoizer{values: map[string]any{}}
	if _, err := newRX(plugintypes.OperatorOptions{
		Arguments:          "needle",
		Memoizer:           memoizer,
		RxPreFilterEnabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if memoizer.lastKey == "" {
		t.Fatal("regex did not use the memoizer")
	}

	var datasetOperator plugintypes.Operator
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("dataset cache key collided with another operator: %v", recovered)
			}
		}()
		var err error
		datasetOperator, err = newPMFromDataset(plugintypes.OperatorOptions{
			Arguments: memoizer.lastKey,
			Datasets:  map[string][]string{memoizer.lastKey: {"blocked"}},
			Memoizer:  memoizer,
		})
		if err != nil {
			t.Fatal(err)
		}
	}()

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
	if !datasetOperator.Evaluate(tx, "blocked") {
		t.Fatal("dataset operator did not compile its own matcher")
	}
}

type operatorTestMemoizer struct {
	values  map[string]any
	lastKey string
}

func (memoizer *operatorTestMemoizer) Do(key string, compile func() (any, error)) (any, error) {
	memoizer.lastKey = key
	if value, ok := memoizer.values[key]; ok {
		return value, nil
	}
	value, err := compile()
	if err == nil {
		memoizer.values[key] = value
	}
	return value, err
}
