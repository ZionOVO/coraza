// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package operators

import (
	"testing"
	"testing/fstest"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestMemoizedOperatorArtifactsUseDistinctNamespaces(t *testing.T) {
	const schemaPath = "schema.json"
	schemaData := []byte(`{"type":"object"}`)
	sharedExpression := schemaCacheKey(schemaData)
	memoizer := &namespaceTestMemoizer{values: map[string]any{}}

	if _, err := newRESTPath(plugintypes.OperatorOptions{
		Arguments: sharedExpression,
		Memoizer:  memoizer,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := newValidateNID(plugintypes.OperatorOptions{
		Arguments: "us " + sharedExpression,
		Memoizer:  memoizer,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewValidateSchema(plugintypes.OperatorOptions{
		Arguments: schemaPath,
		Root: fstest.MapFS{
			schemaPath: {Data: schemaData},
		},
		Memoizer: memoizer,
	}); err != nil {
		t.Fatal(err)
	}

	if len(memoizer.values) != 3 {
		t.Fatalf("three artifact types produced %d cache entries", len(memoizer.values))
	}
}

type namespaceTestMemoizer struct {
	values map[string]any
}

func (memoizer *namespaceTestMemoizer) Do(key string, compile func() (any, error)) (any, error) {
	if value, ok := memoizer.values[key]; ok {
		return value, nil
	}
	value, err := compile()
	if err == nil {
		memoizer.values[key] = value
	}
	return value, err
}
