// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// rxprefilter implements compile-time analysis of regex patterns to build cheap
// pre-checks that can skip expensive regexp.Regexp evaluation when the input
// clearly cannot match.
//
// Why this exists:
//
// CRS loads hundreds of @rx rules and each one is evaluated against every
// relevant variable value per request. For typical benign traffic, the vast majority of
// these evaluations return false. The regex engine still has to run in full
// before concluding "no match". This file provides two mechanisms to short-
// circuit that work:
//
//  1. Minimum match length — computed by walking the regexp/syntax AST. If the
//     input is shorter than the minimum number of bytes the pattern could ever
//     match, we skip the regex entirely.
//
//  2. Required literal pre-filtering — also extracted from the AST. Every regex
//     has certain literal substrings that *must* appear in any matching input.
//     For example, `sleep\s*\(` always requires "sleep" and "(". If we can
//     cheaply confirm those literals are absent (via strings.Contains for a
//     single literal, or an Aho-Corasick automaton for alternations), we know
//     the regex cannot match and skip it.
//
// Safety guarantee:
//
// The prefilter can only produce two outcomes:
//   - "definitely no match" → skip regex (correct: required literals absent)
//   - "maybe match" → run regex (conservative: may still not match)
//
// A bug in literal extraction can only make the prefilter say "maybe" too
// often (degraded performance), never cause a false negative (missed attack).
// This is safe by construction — the prefilter is a necessary-condition check,
// not a sufficient-condition check.
//
// Design principle: when in doubt, fall back to the regex. The prefilter is
// purely an optimization. If there is any uncertainty about whether the input
// could match (e.g., non-ASCII input with case-insensitive patterns, unknown
// AST nodes, unparseable patterns), we return "maybe match" and let the full
// regex engine make the final decision. A missed optimization is free; a missed
// attack is a security vulnerability.
//
// AST walk rules for literal extraction (extractLiterals):
//
//   - OpLiteral → the literal string itself (required)
//   - OpConcat  → collect required literals from all children
//   - OpAlternate → at least one branch must match, so we pick the best
//     literal from each branch and build an "any of these" check
//   - OpCapture / OpPlus / OpRepeat(min>=1) → recurse into sub-expression
//   - OpStar / OpQuest / OpRepeat(min==0) → skip (optional, no guarantee)
//   - When (?i) is set, literals are lowercased and compared case-insensitively
//
// AST walk rules for minimum length (minLen):
//
//   - OpLiteral → byte length of the runes
//   - OpConcat  → sum of children
//   - OpAlternate → minimum across children
//   - OpPlus → child minimum (at least one repetition)
//   - OpStar / OpQuest → 0
//   - OpRepeat → re.Min * child minimum
//   - OpCharClass / OpAnyChar → 1

package operators

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// minMatchLength computes the minimum number of bytes an input must have
// for the compiled regex to possibly match. Returns 0 when unknown.
func minMatchLength(pattern string) int {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0
	}
	re = re.Simplify()
	return minLen(re)
}

// minLen computes the minimum byte length a matching input must have for the
// given regex AST node. Returns 0 for unknown or optional nodes.
func minLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		// Count byte length per rune. U+FFFD (RuneError) is special: Go's
		// regexp engine matches it against a single invalid UTF-8 byte (1 byte),
		// but its UTF-8 encoding is 3 bytes. Count it as 1 to avoid rejecting
		// inputs that the regex would actually match.
		n := 0
		for _, r := range re.Rune {
			if r == utf8.RuneError {
				n++
			} else {
				n += utf8.RuneLen(r)
			}
		}
		return n
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar, syntax.OpCharClass:
		// Any single character match requires at least 1 byte.
		return 1
	case syntax.OpCapture:
		// Capture groups don't add length, just recurse into the content.
		return minLen(re.Sub[0])
	case syntax.OpConcat:
		// All parts of a concatenation must match, so sum their minimums.
		n := 0
		for _, sub := range re.Sub {
			n += minLen(sub)
		}
		return n
	case syntax.OpAlternate:
		// Only one branch needs to match, so take the shortest branch.
		// Defensive: syntax.Parse never produces an empty OpAlternate after Simplify,
		// but guard anyway to avoid an index-out-of-bounds panic.
		if len(re.Sub) == 0 {
			return 0
		}
		m := minLen(re.Sub[0])
		for _, sub := range re.Sub[1:] {
			if v := minLen(sub); v < m {
				m = v
			}
		}
		return m
	case syntax.OpQuest, syntax.OpStar:
		// ? and * can match zero repetitions.
		return 0
	case syntax.OpPlus:
		// + requires at least one repetition.
		return minLen(re.Sub[0])
	case syntax.OpRepeat:
		// {n,m} requires at least n repetitions.
		// Note: syntax.Regexp.Simplify() expands counted repetitions into
		// OpConcat/OpQuest nodes, so this case is unreachable when minLen
		// is called after Simplify(). Kept as a correct fallback.
		if re.Min == 0 {
			return 0
		}
		return re.Min * minLen(re.Sub[0])
	default:
		// Unknown ops (e.g. OpBeginLine, OpEndLine) don't consume input.
		return 0
	}
}

// prefilterFunc returns a function that returns true if the regex might match
// the input, false if it definitely cannot. Returns nil when no useful
// prefilter can be built.
type compiledPrefilter struct {
	match          func(string) bool
	matchWithState func(plugintypes.TransactionState, string) bool
}

func prefilterFunc(pattern string) func(string) bool {
	return compilePrefilter(pattern).match
}

func compilePrefilter(pattern string) compiledPrefilter {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return compiledPrefilter{}
	}
	re = re.Simplify()

	caseInsensitive := hasFlag(re, syntax.FoldCase)

	lits := extractLiterals(re, caseInsensitive)
	if lits == nil {
		return compiledPrefilter{}
	}
	// Byte-level case folding is only equivalent to Go's regular-expression
	// folding for ASCII literals. In particular, a cached bitmap for "é" would
	// reject "É" before the regular-expression engine can apply Unicode folding.
	if caseInsensitive && !extractedLiteralsAreASCII(lits) {
		return compiledPrefilter{}
	}

	var pf func(string) bool
	var cacheMatcher *requiredByteMatcher
	populateCache := false

	switch v := lits.(type) {
	case allRequired:
		// allRequired: every literal must be present in the input.
		// Example: pattern "hello.*world" yields allRequired{"hello", "world"}.
		// We check each with strings.Contains; if any is absent, regex can't match.
		filtered := filterShort(v, 2)
		if len(filtered) == 0 {
			// A one-byte required literal is still useful when no longer literal
			// exists. Keep one necessary byte instead of abandoning the filter.
			filtered = []string{longest(v)}
		}
		switch {
		case len(filtered) == 1:
			needle := filtered[0]
			if caseInsensitive {
				matcher := newFoldedLiteralMatcher(needle)
				pf = matcher.match
			} else {
				pf = func(s string) bool {
					return strings.Contains(s, needle)
				}
			}
		case caseInsensitive:
			matchers := newFoldedLiteralMatchers(filtered)
			pf = func(s string) bool {
				for _, matcher := range matchers {
					if !matcher.match(s) {
						return false
					}
				}
				return true
			}
		default:
			pf = func(s string) bool {
				for _, needle := range filtered {
					if !strings.Contains(s, needle) {
						return false
					}
				}
				return true
			}
		}
		cacheMatcher = newRequiredByteMatcher([]string{longest(filtered)}, caseInsensitive)
	case anyRequired:
		// anyRequired: at least one literal must be present in the input.
		// Example: pattern "(?:union|insert)" yields anyRequired{"union", "insert"}.
		// We use Aho-Corasick to scan for any of them in a single pass.
		//
		// SAFETY: Do not filter short alternatives. Removing one changes the
		// semantics and can create a false negative. Empty alternatives cannot
		// constrain a match, while one-byte alternatives remain in the matcher.
		if anyTooShort(v, 1) {
			return compiledPrefilter{}
		}
		filtered := v
		switch {
		case len(filtered) == 1:
			needle := filtered[0]
			if caseInsensitive {
				matcher := newFoldedLiteralMatcher(needle)
				pf = matcher.match
			} else {
				pf = func(s string) bool {
					return strings.Contains(s, needle)
				}
			}
		case caseInsensitive && !allASCIIStrings([]string(filtered)):
			// When case-insensitive, Aho-Corasick uses ASCII-only folding. If any
			// needle is non-ASCII (e.g. "ſelect" lowercased from "Select"), it could
			// fold to an ASCII equivalent under Go's Unicode case rules — meaning a
			// pure-ASCII input like "select" would match (?i)ſelect but the automaton
			// wouldn't find "ſelect" in "select". To avoid false negatives, bail out.
			return compiledPrefilter{}
		case anyTooShort(filtered, 2):
			// Multiple independent one-byte searches rescan large bodies. A
			// required-byte set handles short and long alternatives in one pass.
			cacheMatcher = newRequiredByteMatcher(filtered, caseInsensitive)
			populateCache = true
			pf = cacheMatcher.match
		case len(filtered) <= linearAnyRequiredMaxNeedles && caseInsensitive:
			matchers := newFoldedLiteralMatchers(filtered)
			pf = func(s string) bool {
				for _, matcher := range matchers {
					if matcher.match(s) {
						return true
					}
				}
				return false
			}
		case len(filtered) <= linearAnyRequiredMaxNeedles:
			pf = func(s string) bool {
				for _, needle := range filtered {
					if strings.Contains(s, needle) {
						return true
					}
				}
				return false
			}
		case len(filtered) <= anyRequiredMaxNeedles:
			matcher := newIndexedMatcher(filtered, caseInsensitive)
			pf = matcher.match
		default:
			// A dense exact matcher becomes expensive for assembled rules with
			// thousands of alternatives. Every alternative still contains either
			// a required byte or byte pair, which gives a bounded coarse filter.
			cacheMatcher = newRequiredByteMatcher(filtered, caseInsensitive)
			populateCache = true
			pf = cacheMatcher.match
		}
		if cacheMatcher == nil {
			cacheMatcher = newRequiredByteMatcher(filtered, caseInsensitive)
		}
	}

	if pf == nil {
		return compiledPrefilter{}
	}
	var stateful func(plugintypes.TransactionState, string) bool
	if populateCache {
		stateful = cacheMatcher.matchWithState
	} else if cacheMatcher != nil {
		baseMatch := pf
		stateful = func(tx plugintypes.TransactionState, value string) bool {
			if !cacheMatcher.possibleFromCache(tx, value) {
				return false
			}
			return baseMatch(value)
		}
	}

	// When case-insensitive matching is active, the prefilter performs ASCII
	// folding. Go regular expressions additionally fold ASCII s and k with the
	// non-ASCII long-s and Kelvin-sign runes. Check those two exceptions after
	// a negative prefilter result instead of scanning the whole input up front.
	if caseInsensitive {
		inner := pf
		pf = func(s string) bool {
			if inner(s) {
				return true
			}
			return strings.Contains(s, "ſ") || strings.Contains(s, "K")
		}
		if stateful != nil {
			innerStateful := stateful
			stateful = func(tx plugintypes.TransactionState, s string) bool {
				if innerStateful(tx, s) {
					return true
				}
				return strings.Contains(s, "ſ") || strings.Contains(s, "K")
			}
		}
	}

	return compiledPrefilter{match: pf, matchWithState: stateful}
}

// literal extraction types

// allRequired means every string in the slice must appear in the input.
type allRequired []string

// anyRequired means at least one string in the slice must appear in the input.
type anyRequired []string

func extractedLiteralsAreASCII(literals interface{}) bool {
	switch values := literals.(type) {
	case allRequired:
		return allASCIIStrings(values)
	case anyRequired:
		return allASCIIStrings(values)
	default:
		return false
	}
}

// extractLiterals walks the regex AST and returns the required literal substrings
// that must appear in any input for the regex to match. Returns:
//   - allRequired: every literal must be present (from concatenation)
//   - anyRequired: at least one literal must be present (from alternation)
//   - nil: no useful literals could be extracted
//
// The ci parameter controls case-insensitive mode: when true, extracted
// literals are lowercased so the caller can compare case-insensitively.
func extractLiterals(re *syntax.Regexp, ci bool) interface{} {
	switch re.Op {
	case syntax.OpLiteral:
		// U+FFFD in a literal matches single invalid UTF-8 bytes in Go's regexp,
		// but strings.Contains searches for the 3-byte encoding. Bail out to
		// avoid false negatives.
		for _, r := range re.Rune {
			if r == utf8.RuneError {
				return nil
			}
		}
		s := string(re.Rune)
		if ci {
			s = strings.ToLower(s)
		}
		return allRequired{s}

	case syntax.OpCharClass:
		// Small positive byte classes are useful alternatives in assembled
		// expressions, especially punctuation branches such as [;{}]. Large,
		// Unicode, and negated classes stay with the full regex engine.
		const maxClassLiterals = 64
		var literals []string
		for index := 0; index+1 < len(re.Rune); index += 2 {
			low, high := re.Rune[index], re.Rune[index+1]
			if low < 0 || high > unicode.MaxASCII || high-low+1 > maxClassLiterals-int32(len(literals)) {
				return nil
			}
			for value := low; value <= high; value++ {
				literal := string(value)
				if ci {
					literal = strings.ToLower(literal)
				}
				literals = append(literals, literal)
			}
		}
		if len(literals) == 0 {
			return nil
		}
		return anyRequired(literals)

	case syntax.OpCapture:
		// Capture groups are transparent for literal extraction.
		return extractLiterals(re.Sub[0], ci)

	case syntax.OpConcat:
		var all []string
		var alternatives []anyRequired
		for _, sub := range re.Sub {
			lits := extractLiterals(sub, ci)
			if lits == nil {
				continue
			}
			switch v := lits.(type) {
			case allRequired:
				all = append(all, v...)
			case anyRequired:
				// Every concatenated child must match. Preserve its complete
				// alternative set as one possible necessary-condition filter.
				alternatives = append(alternatives, v)
			}
		}
		best := bestAnyRequired(alternatives)
		if len(all) != 0 {
			// Both conditions are necessary. Prefer an alternative group only
			// when even its shortest literal is longer than the strongest fixed
			// literal; this avoids reducing factored words such as x(?:args|term)
			// to the unselective one-byte prefix x.
			if len(best) != 0 && shortestLength(best) > len(longest(all)) {
				return best
			}
			return allRequired(all)
		}
		if len(best) == 0 {
			return nil
		}
		return best

	case syntax.OpAlternate:
		// For alternation (a|b|c), exactly one branch must match. So we need
		// at least one branch's required literal to be present in the input.
		// From each branch we pick its longest literal as the representative.
		// If any branch has no extractable literal, we can't pre-filter at all
		// because that branch could match without any of our literals.
		var branchLits []string
		for _, sub := range re.Sub {
			lits := extractLiterals(sub, ci)
			if lits == nil {
				// One branch has no extractable literal → can't pre-filter
				return nil
			}
			switch v := lits.(type) {
			case allRequired:
				// Pick the longest literal from this branch as its representative.
				branchLits = append(branchLits, longest(v))
			case anyRequired:
				// A nested alternation: any of its elements could satisfy this
				// branch. Merge all into the parent anyRequired — we can't pick
				// just one without risking false negatives.
				// Example: pattern `10|(10|00)` — branch B is anyRequired{"10","00"},
				// if we only kept "10" we'd miss input "00".
				branchLits = append(branchLits, v...)
			}
		}
		if len(branchLits) == 0 {
			return nil
		}
		return anyRequired(branchLits)

	case syntax.OpPlus:
		return extractLiterals(re.Sub[0], ci)

	case syntax.OpRepeat:
		if re.Min >= 1 {
			return extractLiterals(re.Sub[0], ci)
		}
		return nil

	case syntax.OpQuest, syntax.OpStar:
		return nil

	default:
		return nil
	}
}

func bestAnyRequired(groups []anyRequired) anyRequired {
	var best anyRequired
	bestMinLen := 0
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		minLen := len(group[0])
		for _, literal := range group[1:] {
			if len(literal) < minLen {
				minLen = len(literal)
			}
		}
		if minLen > bestMinLen || minLen == bestMinLen && (best == nil || len(group) < len(best)) {
			best = group
			bestMinLen = minLen
		}
	}
	return best
}

func shortestLength(values []string) int {
	if len(values) == 0 {
		return 0
	}
	shortest := len(values[0])
	for _, value := range values[1:] {
		if len(value) < shortest {
			shortest = len(value)
		}
	}
	return shortest
}

// hasFlag reports whether the flag is set on any node in the regex tree.
// Flags in Go's regexp/syntax can be scoped to sub-expressions (e.g. (?i:...)),
// so a top-level-only check would miss flags applied further down the tree.
func hasFlag(re *syntax.Regexp, flag syntax.Flags) bool {
	if re.Flags&flag != 0 {
		return true
	}
	for _, sub := range re.Sub {
		if hasFlag(sub, flag) {
			return true
		}
	}
	return false
}

// longest returns the longest string in ss, or "" if ss is empty.
func longest(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	best := ss[0]
	for _, s := range ss[1:] {
		if len(s) > len(best) {
			best = s
		}
	}
	return best
}

// anyTooShort returns true if any string in ss is shorter than minLen bytes.
// Used for anyRequired: if any alternative is too short, we can't safely filter
// because removing it would change "one of {A,B,C}" to "one of {A,B}" semantics.
func anyTooShort(ss []string, minLen int) bool {
	for _, s := range ss {
		if len(s) < minLen {
			return true
		}
	}
	return false
}

// filterShort removes strings shorter than minLen bytes. Very short literals
// (e.g. single characters) are too common across inputs to be effective filters.
// SAFETY: Only safe for allRequired (removing a needle makes the check less strict).
// Never use for anyRequired — use anyTooShort instead.
func filterShort(ss []string, minLen int) []string {
	result := ss[:0:0]
	for _, s := range ss {
		if len(s) >= minLen {
			result = append(result, s)
		}
	}
	return result
}

// anyRequiredMaxNeedles bounds the pattern set used by indexedMatcher. Above
// this count its shift table tends to saturate and loses its sub-linear skips.
const anyRequiredMaxNeedles = 256

// Small literal sets are faster as independent byte searches because the
// standard library uses platform-optimized substring search for each needle.
const linearAnyRequiredMaxNeedles = 32

// requiredByteMatcher is a bounded coarse filter for very large alternative
// sets. Its byte set intersects every alternative literal, so a matching input
// must contain at least one selected byte. False positives are allowed; false
// negatives are not.
type requiredByteMatcher struct {
	bytes      [256]bool
	bits       [4]uint64
	characters string
	ascii      bool
}

type bytePresenceCache interface {
	LoadBytePresence(string) (*[4]uint64, bool)
	StoreBytePresence(string, [4]uint64)
}

const cachedBytePresenceMinInputBytes = 512

func newRequiredByteMatcher(needles []string, caseFold bool) *requiredByteMatcher {
	groups := make([][]byte, 0, len(needles))
	for _, needle := range needles {
		var present [256]bool
		group := make([]byte, 0, len(needle))
		for index := range len(needle) {
			value := needle[index]
			if !present[value] {
				present[value] = true
				group = append(group, value)
			}
		}
		groups = append(groups, group)
	}

	matcher := &requiredByteMatcher{}
	covered := make([]bool, len(groups))
	remaining := len(groups)
	for remaining > 0 {
		var counts [256]int
		for index, group := range groups {
			if covered[index] {
				continue
			}
			for _, value := range group {
				counts[value]++
			}
		}
		best := byte(0)
		for value := 1; value < len(counts); value++ {
			if counts[value] > counts[best] ||
				counts[value] == counts[best] && byteRarity(byte(value)) > byteRarity(best) {
				best = byte(value)
			}
		}
		matcher.add(best, caseFold)
		for index, group := range groups {
			if covered[index] || !containsByte(group, best) {
				continue
			}
			covered[index] = true
			remaining--
		}
	}
	var characters strings.Builder
	matcher.ascii = true
	for value, selected := range matcher.bytes {
		if !selected {
			continue
		}
		if value >= utf8.RuneSelf {
			matcher.ascii = false
			break
		}
		characters.WriteByte(byte(value))
	}
	if matcher.ascii {
		matcher.characters = characters.String()
	}
	return matcher
}

func byteRarity(value byte) int {
	switch value {
	case 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r':
		return 0
	case 'd', 'l', 'u', 'c', 'm', 'f', 'y', 'w', 'g', 'p', 'b', 'v':
		return 1
	case 'k', 'j', 'q', 'x', 'z':
		return 2
	default:
		return 3
	}
}

func (matcher *requiredByteMatcher) match(value string) bool {
	if matcher.ascii {
		return strings.ContainsAny(value, matcher.characters)
	}
	for index := range len(value) {
		current := value[index]
		if matcher.bytes[current] {
			return true
		}
	}
	return false
}

func (matcher *requiredByteMatcher) matchWithState(tx plugintypes.TransactionState, value string) bool {
	cache, ok := tx.(bytePresenceCache)
	if !ok || len(value) < cachedBytePresenceMinInputBytes {
		return matcher.match(value)
	}
	if present, found := cache.LoadBytePresence(value); found {
		for index := range matcher.bits {
			if present[index]&matcher.bits[index] != 0 {
				return true
			}
		}
		return false
	}
	if matcher.match(value) {
		return true
	}
	var present [4]uint64
	for index := range len(value) {
		current := value[index]
		present[current>>6] |= uint64(1) << (current & 63)
	}
	cache.StoreBytePresence(value, present)
	return false
}

func (matcher *requiredByteMatcher) possibleFromCache(tx plugintypes.TransactionState, value string) bool {
	cache, ok := tx.(bytePresenceCache)
	if !ok || len(value) < cachedBytePresenceMinInputBytes {
		return true
	}
	present, found := cache.LoadBytePresence(value)
	if !found {
		return true
	}
	for index := range matcher.bits {
		if present[index]&matcher.bits[index] != 0 {
			return true
		}
	}
	return false
}

func (matcher *requiredByteMatcher) add(value byte, caseFold bool) {
	matcher.bytes[value] = true
	matcher.bits[value>>6] |= uint64(1) << (value & 63)
	if caseFold && value >= 'a' && value <= 'z' {
		upper := value - ('a' - 'A')
		matcher.bytes[upper] = true
		matcher.bits[upper>>6] |= uint64(1) << (upper & 63)
	}
}

func containsByte(values []byte, target byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// indexedMatcher implements a Wu-Manber-style multi-pattern search. It uses
// the shortest needle as a window and only verifies candidates when the byte
// at the window edge can end a needle prefix.
type indexedMatcher struct {
	shift       [256]uint8
	endBuckets  [256][]string
	pairShift   []uint8
	pairBuckets map[uint16][]string
	minLen      int
	caseFold    bool
	required    *requiredByteMatcher
}

func newIndexedMatcher(needles []string, caseFold bool) *indexedMatcher {
	if len(needles) == 0 {
		return &indexedMatcher{caseFold: caseFold}
	}
	normalized := needles
	if caseFold {
		normalized = make([]string, len(needles))
		for i, needle := range needles {
			normalized[i] = lowerASCII(needle)
		}
	}
	matcher := &indexedMatcher{
		caseFold: caseFold,
		minLen:   len(normalized[0]),
		required: newRequiredByteMatcher(normalized, caseFold),
	}
	for _, needle := range normalized[1:] {
		if len(needle) < matcher.minLen {
			matcher.minLen = len(needle)
		}
	}
	if matcher.minLen >= 2 {
		matcher.buildPairIndex(normalized)
		return matcher
	}

	maxShift := matcher.minLen
	if maxShift > 255 {
		maxShift = 255
	}
	for i := range matcher.shift {
		matcher.shift[i] = uint8(maxShift)
	}

	for _, needle := range normalized {
		for i := 0; i < matcher.minLen; i++ {
			shift := uint8(matcher.minLen - 1 - i)
			c := needle[i]
			if shift < matcher.shift[c] {
				matcher.shift[c] = shift
			}
			if caseFold && c >= 'a' && c <= 'z' {
				upper := c - ('a' - 'A')
				if shift < matcher.shift[upper] {
					matcher.shift[upper] = shift
				}
			}
		}
	}
	for _, needle := range normalized {
		c := needle[matcher.minLen-1]
		matcher.endBuckets[c] = append(matcher.endBuckets[c], needle)
	}
	return matcher
}

func (matcher *indexedMatcher) buildPairIndex(needles []string) {
	matcher.pairShift = make([]uint8, 1<<16)
	maxShift := matcher.minLen - 1
	if maxShift > 255 {
		maxShift = 255
	}
	for i := range matcher.pairShift {
		matcher.pairShift[i] = uint8(maxShift)
	}
	for _, needle := range needles {
		for i := 0; i <= matcher.minLen-2; i++ {
			shift := uint8(matcher.minLen - 2 - i)
			pair := bytePair(needle[i], needle[i+1])
			if shift < matcher.pairShift[pair] {
				matcher.pairShift[pair] = shift
			}
		}
	}
	matcher.pairBuckets = make(map[uint16][]string, len(needles))
	for _, needle := range needles {
		pair := bytePair(needle[matcher.minLen-2], needle[matcher.minLen-1])
		matcher.pairBuckets[pair] = append(matcher.pairBuckets[pair], needle)
	}
}

func bytePair(first, second byte) uint16 {
	return uint16(first)<<8 | uint16(second)
}

func foldedBytePair(first, second byte) uint16 {
	if first >= 'A' && first <= 'Z' {
		first += 'a' - 'A'
	}
	if second >= 'A' && second <= 'Z' {
		second += 'a' - 'A'
	}
	return bytePair(first, second)
}

func (matcher *indexedMatcher) match(value string) bool {
	if matcher.caseFold {
		return matcher.matchFold(value)
	}
	return matcher.matchCaseSensitive(value)
}

func (matcher *indexedMatcher) matchWithState(tx plugintypes.TransactionState, value string) bool {
	if matcher.required != nil && !matcher.required.possibleFromCache(tx, value) {
		return false
	}
	return matcher.match(value)
}

func (matcher *indexedMatcher) matchCaseSensitive(value string) bool {
	minLen := matcher.minLen
	if minLen == 0 || len(value) < minLen {
		return false
	}
	if matcher.pairShift != nil {
		for end := minLen - 1; end < len(value); {
			pair := bytePair(value[end-1], value[end])
			shift := matcher.pairShift[pair]
			if shift != 0 {
				end += int(shift)
				continue
			}
			start := end - minLen + 1
			for _, needle := range matcher.pairBuckets[pair] {
				if matchEnd := start + len(needle); matchEnd <= len(value) && value[start:matchEnd] == needle {
					return true
				}
			}
			end++
		}
		return false
	}
	for index := minLen - 1; index < len(value); {
		shift := matcher.shift[value[index]]
		if shift != 0 {
			index += int(shift)
			continue
		}
		start := index - minLen + 1
		for _, needle := range matcher.endBuckets[value[index]] {
			if end := start + len(needle); end <= len(value) && value[start:end] == needle {
				return true
			}
		}
		index++
	}
	return false
}

func (matcher *indexedMatcher) matchFold(value string) bool {
	minLen := matcher.minLen
	if minLen == 0 || len(value) < minLen {
		return false
	}
	if matcher.pairShift != nil {
		for end := minLen - 1; end < len(value); {
			pair := foldedBytePair(value[end-1], value[end])
			shift := matcher.pairShift[pair]
			if shift != 0 {
				end += int(shift)
				continue
			}
			start := end - minLen + 1
			for _, needle := range matcher.pairBuckets[pair] {
				if matchEnd := start + len(needle); matchEnd <= len(value) && equalFoldASCIIBytes(value[start:matchEnd], needle) {
					return true
				}
			}
			end++
		}
		return false
	}
	for index := minLen - 1; index < len(value); {
		c := value[index]
		shift := matcher.shift[c]
		if shift != 0 {
			index += int(shift)
			continue
		}
		lower := c
		if lower >= 'A' && lower <= 'Z' {
			lower += 'a' - 'A'
		}
		start := index - minLen + 1
		for _, needle := range matcher.endBuckets[lower] {
			if end := start + len(needle); end <= len(value) && equalFoldASCIIBytes(value[start:end], needle) {
				return true
			}
		}
		index++
	}
	return false
}

func equalFoldASCIIBytes(value, lower string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

func lowerASCII(value string) string {
	for index := range len(value) {
		if value[index] < 'A' || value[index] > 'Z' {
			continue
		}
		lower := []byte(value)
		for offset := index; offset < len(lower); offset++ {
			if lower[offset] >= 'A' && lower[offset] <= 'Z' {
				lower[offset] += 'a' - 'A'
			}
		}
		return string(lower)
	}
	return value
}

// containsFoldASCII does a case-insensitive substring check.
// needle must already be lowercase.
func containsFoldASCII(s, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(s) < len(needle) {
		return false
	}
	// Fast path: check if all needle bytes are ASCII for simpler comparison.
	if isASCII(needle) {
		return containsFoldASCIIOnly(s, needle)
	}
	// For non-ASCII needles, strings.ToLower does not implement the same
	// Unicode folding rules as regexp/syntax.FoldCase (e.g., Greek sigma has
	// multiple fold equivalents). To preserve correctness, we conservatively
	// return true ("maybe match") and let the full regex decide.
	return true
}

const asciiWordSize = 4 << (^uintptr(0) >> 63)
const asciiHighBits = 0x8080808080808080 >> (64 - 8*asciiWordSize)

func asciiWord(s string) uintptr {
	if asciiWordSize == 4 {
		return uintptr(s[0]) | uintptr(s[1])<<8 | uintptr(s[2])<<16 | uintptr(s[3])<<24
	}
	return uintptr(uint64(s[0]) | uint64(s[1])<<8 | uint64(s[2])<<16 | uint64(s[3])<<24 |
		uint64(s[4])<<32 | uint64(s[5])<<40 | uint64(s[6])<<48 | uint64(s[7])<<56)
}

// isASCII reports whether s contains only ASCII bytes. Word-sized loads share
// one high-bit check because this function also guards large regex inputs.
func isASCII(s string) bool {
	for len(s) >= 4*asciiWordSize {
		if (asciiWord(s)|asciiWord(s[asciiWordSize:])|
			asciiWord(s[2*asciiWordSize:])|asciiWord(s[3*asciiWordSize:]))&asciiHighBits != 0 {
			return false
		}
		s = s[4*asciiWordSize:]
	}
	for len(s) >= asciiWordSize {
		if asciiWord(s)&asciiHighBits != 0 {
			return false
		}
		s = s[asciiWordSize:]
	}
	for index := range len(s) {
		if s[index] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func allASCIIStrings(ss []string) bool {
	for _, s := range ss {
		if !isASCII(s) {
			return false
		}
	}
	return true
}

// containsFoldASCIIOnly is a brute-force case-insensitive substring search
// optimized for ASCII-only needles. It lowercases each byte of s inline
// (only A-Z → a-z) and compares against needle which must already be lowercase.
// This avoids allocating a lowercased copy of s.
func containsFoldASCIIOnly(s, needle string) bool {
	nlen := len(needle)
	if nlen == 0 {
		return true
	}
	lastStart := len(s) - nlen
	if lastStart < 0 {
		return false
	}
	anchorOffset := 0
	for index := 1; index < len(needle); index++ {
		if byteRarity(needle[index]) > byteRarity(needle[anchorOffset]) {
			anchorOffset = index
		}
	}
	lower := needle[anchorOffset]
	upper := lower
	if upper >= 'a' && upper <= 'z' {
		upper -= 'a' - 'A'
	}
	for searchStart, lastAnchor := anchorOffset, lastStart+anchorOffset; searchStart <= lastAnchor; {
		candidates := s[searchStart : lastAnchor+1]
		next := strings.IndexByte(candidates, lower)
		if upper != lower {
			upperNext := strings.IndexByte(candidates, upper)
			if next < 0 || upperNext >= 0 && upperNext < next {
				next = upperNext
			}
		}
		if next < 0 {
			return false
		}
		anchor := searchStart + next
		candidate := anchor - anchorOffset
		if equalFoldASCIIBytes(s[candidate:candidate+nlen], needle) {
			return true
		}
		searchStart = anchor + 1
	}
	return false
}

type foldedLiteralMatcher struct {
	needle      string
	shift       [256]uint16
	anchorLower byte
	anchorUpper byte
	indexed     bool
}

func newFoldedLiteralMatchers(needles []string) []*foldedLiteralMatcher {
	matchers := make([]*foldedLiteralMatcher, len(needles))
	for index, needle := range needles {
		matchers[index] = newFoldedLiteralMatcher(needle)
	}
	return matchers
}

func newFoldedLiteralMatcher(needle string) *foldedLiteralMatcher {
	matcher := &foldedLiteralMatcher{needle: needle}
	if len(needle) < 2 || !isASCII(needle) {
		return matcher
	}
	anchor := 0
	for index := 1; index < len(needle); index++ {
		if byteRarity(needle[index]) > byteRarity(needle[anchor]) {
			anchor = index
		}
	}
	matcher.anchorLower = needle[anchor]
	matcher.anchorUpper = matcher.anchorLower
	if matcher.anchorUpper >= 'a' && matcher.anchorUpper <= 'z' {
		matcher.anchorUpper -= 'a' - 'A'
	}
	defaultShift := len(needle)
	if defaultShift > int(^uint16(0)) {
		defaultShift = int(^uint16(0))
	}
	for index := range matcher.shift {
		matcher.shift[index] = uint16(defaultShift)
	}
	for index := 0; index < len(needle)-1; index++ {
		shift := len(needle) - 1 - index
		if shift > int(^uint16(0)) {
			shift = int(^uint16(0))
		}
		lower := needle[index]
		if lower >= 'A' && lower <= 'Z' {
			lower += 'a' - 'A'
		}
		if uint16(shift) < matcher.shift[lower] {
			matcher.shift[lower] = uint16(shift)
		}
		if lower >= 'a' && lower <= 'z' {
			matcher.shift[lower-('a'-'A')] = matcher.shift[lower]
		}
	}
	matcher.indexed = true
	return matcher
}

func (matcher *foldedLiteralMatcher) match(value string) bool {
	if !matcher.indexed {
		return containsFoldASCII(value, matcher.needle)
	}
	if strings.IndexByte(value, matcher.anchorLower) < 0 &&
		(matcher.anchorUpper == matcher.anchorLower || strings.IndexByte(value, matcher.anchorUpper) < 0) {
		return false
	}
	needleLen := len(matcher.needle)
	for end := needleLen - 1; end < len(value); {
		start := end - needleLen + 1
		if equalFoldASCIIBytes(value[start:end+1], matcher.needle) {
			return true
		}
		current := value[end]
		if current >= 'A' && current <= 'Z' {
			current += 'a' - 'A'
		}
		end += int(matcher.shift[current])
	}
	return false
}

// extractExactMatch reports whether re is a pure anchored literal equality
// check. The caller parses the original rule expression without Coraza's
// default multiline wrapper so line anchors retain their original meaning.
func extractExactMatch(re *syntax.Regexp) (literal string, caseInsensitive bool) {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpConcat || len(re.Sub) != 3 {
		return "", false
	}
	begin, middle, end := re.Sub[0], re.Sub[1], re.Sub[2]
	if begin.Op != syntax.OpBeginText || end.Op != syntax.OpEndText || middle.Op != syntax.OpLiteral {
		return "", false
	}
	for _, r := range middle.Rune {
		if r == utf8.RuneError {
			return "", false
		}
	}
	return string(middle.Rune), middle.Flags&syntax.FoldCase != 0
}
