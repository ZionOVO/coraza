// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/types/variables"
)

// Match is an internal read-only view of one collection value.
type Match struct {
	Variable variables.RuleVariable
	Key      string
	Value    string
}

// MatchAppender appends collection values without materializing MatchData interfaces.
type MatchAppender interface {
	AppendMatches([]Match) []Match
}

// KeyedMatchAppender appends selected keyed values without materializing MatchData interfaces.
type KeyedMatchAppender interface {
	MatchAppender
	AppendMatchesRegex([]Match, *regexp.Regexp) []Match
	AppendMatchesString([]Match, string) []Match
}
