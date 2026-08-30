// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
)

var Noop collection.Collection = &noop{}

type noop struct{}

var _ MatchAppender = &noop{}

func (c *noop) FindAll() []types.MatchData {
	return nil
}

func (c *noop) AppendMatches(result []Match) []Match {
	return result
}

func (c *noop) Name() string {
	return ""
}
