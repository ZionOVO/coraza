// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.rx

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	binarysyntax "rsc.io/binaryregexp/syntax"
)

const (
	maxBinaryRequiredClauses        = 64
	maxBinaryRequiredBytesPerClause = 8
)

type binaryRequiredPrefilter struct {
	minimumBytes int
	clauses      []binaryRequiredClause
}

type binaryRequiredClause struct {
	bits  [4]uint64
	bytes string
}

func compileBinaryRequiredPrefilter(pattern string) *binaryRequiredPrefilter {
	re, err := binarysyntax.Parse(pattern, binarysyntax.Perl)
	if err != nil {
		return nil
	}
	constraint, useful := extractBinaryRequiredConstraint(re)
	if !useful || len(constraint) == 0 {
		return nil
	}
	return &binaryRequiredPrefilter{
		minimumBytes: binaryMinimumMatchBytes(re),
		clauses:      constraint,
	}
}

func (filter *binaryRequiredPrefilter) possible(tx plugintypes.TransactionState, value string) bool {
	if len(value) < filter.minimumBytes {
		return false
	}
	cache, cacheAvailable := tx.(bytePresenceCache)
	if cacheAvailable && len(value) >= cachedBytePresenceMinInputBytes {
		if present, found := cache.LoadBytePresence(value); found {
			return filter.possibleFromPresence(present)
		}
	}
	if filter.possibleDirect(value) {
		return true
	}
	if cacheAvailable && len(value) >= cachedBytePresenceMinInputBytes {
		var present [4]uint64
		for index := range len(value) {
			current := value[index]
			present[current>>6] |= uint64(1) << (current & 63)
		}
		cache.StoreBytePresence(value, present)
	}
	return false
}

func (filter *binaryRequiredPrefilter) possibleDirect(value string) bool {
	for _, clause := range filter.clauses {
		possible := true
		for index := range len(clause.bytes) {
			if strings.IndexByte(value, clause.bytes[index]) < 0 {
				possible = false
				break
			}
		}
		if possible {
			return true
		}
	}
	return false
}

func (filter *binaryRequiredPrefilter) possibleFromPresence(present *[4]uint64) bool {
	for _, clause := range filter.clauses {
		possible := true
		for index, required := range clause.bits {
			if present[index]&required != required {
				possible = false
				break
			}
		}
		if possible {
			return true
		}
	}
	return false
}

func extractBinaryRequiredConstraint(re *binarysyntax.Regexp) ([]binaryRequiredClause, bool) {
	switch re.Op {
	case binarysyntax.OpLiteral:
		return binaryLiteralConstraint(re)
	case binarysyntax.OpCapture, binarysyntax.OpPlus:
		if len(re.Sub) != 1 {
			return nil, false
		}
		return extractBinaryRequiredConstraint(re.Sub[0])
	case binarysyntax.OpRepeat:
		if re.Min == 0 || len(re.Sub) != 1 {
			return nil, false
		}
		return extractBinaryRequiredConstraint(re.Sub[0])
	case binarysyntax.OpConcat:
		var combined []binaryRequiredClause
		for _, sub := range re.Sub {
			child, useful := extractBinaryRequiredConstraint(sub)
			if !useful {
				continue
			}
			if len(combined) == 0 {
				combined = child
				continue
			}
			combined = combineBinaryRequiredConstraints(combined, child)
		}
		return combined, len(combined) != 0
	case binarysyntax.OpAlternate:
		var alternatives []binaryRequiredClause
		for _, sub := range re.Sub {
			if sub.Op == binarysyntax.OpNoMatch {
				continue
			}
			child, useful := extractBinaryRequiredConstraint(sub)
			if !useful {
				return nil, false
			}
			if len(alternatives)+len(child) > maxBinaryRequiredClauses {
				return nil, false
			}
			alternatives = append(alternatives, child...)
		}
		return deduplicateBinaryRequiredClauses(alternatives), len(alternatives) != 0
	default:
		return nil, false
	}
}

func binaryLiteralConstraint(re *binarysyntax.Regexp) ([]binaryRequiredClause, bool) {
	var present [256]bool
	values := make([]byte, 0, len(re.Rune))
	for _, value := range re.Rune {
		if value < 0 || value > 255 {
			return nil, false
		}
		current := byte(value)
		if re.Flags&binarysyntax.FoldCase != 0 && ((current >= 'A' && current <= 'Z') || (current >= 'a' && current <= 'z') || current >= 0x80) {
			continue
		}
		if !present[current] {
			present[current] = true
			values = append(values, current)
		}
	}
	if len(values) == 0 {
		return nil, false
	}
	values = selectBinaryRequiredBytes(values)
	return []binaryRequiredClause{newBinaryRequiredClause(values)}, true
}

func combineBinaryRequiredConstraints(left, right []binaryRequiredClause) []binaryRequiredClause {
	if len(left)*len(right) > maxBinaryRequiredClauses {
		if len(right) < len(left) {
			return right
		}
		return left
	}
	combined := make([]binaryRequiredClause, 0, len(left)*len(right))
	for _, leftClause := range left {
		for _, rightClause := range right {
			values := make([]byte, 0, len(leftClause.bytes)+len(rightClause.bytes))
			values = append(values, leftClause.bytes...)
			values = append(values, rightClause.bytes...)
			combined = append(combined, newBinaryRequiredClause(selectBinaryRequiredBytes(values)))
		}
	}
	return deduplicateBinaryRequiredClauses(combined)
}

func selectBinaryRequiredBytes(values []byte) []byte {
	var present [256]bool
	selected := make([]byte, 0, min(len(values), maxBinaryRequiredBytesPerClause))
	for len(selected) < maxBinaryRequiredBytesPerClause {
		bestIndex := -1
		for index, value := range values {
			if present[value] {
				continue
			}
			if bestIndex < 0 || byteRarity(value) > byteRarity(values[bestIndex]) ||
				byteRarity(value) == byteRarity(values[bestIndex]) && value < values[bestIndex] {
				bestIndex = index
			}
		}
		if bestIndex < 0 {
			break
		}
		value := values[bestIndex]
		present[value] = true
		selected = append(selected, value)
	}
	return selected
}

func newBinaryRequiredClause(values []byte) binaryRequiredClause {
	clause := binaryRequiredClause{bytes: string(values)}
	for _, value := range values {
		clause.bits[value>>6] |= uint64(1) << (value & 63)
	}
	return clause
}

func deduplicateBinaryRequiredClauses(clauses []binaryRequiredClause) []binaryRequiredClause {
	seen := make(map[[4]uint64]struct{}, len(clauses))
	result := clauses[:0]
	for _, clause := range clauses {
		if _, found := seen[clause.bits]; found {
			continue
		}
		seen[clause.bits] = struct{}{}
		result = append(result, clause)
	}
	return result
}

func binaryMinimumMatchBytes(re *binarysyntax.Regexp) int {
	switch re.Op {
	case binarysyntax.OpLiteral:
		return len(re.Rune)
	case binarysyntax.OpAnyCharNotNL, binarysyntax.OpAnyChar, binarysyntax.OpCharClass:
		return 1
	case binarysyntax.OpCapture, binarysyntax.OpPlus:
		if len(re.Sub) != 1 {
			return 0
		}
		return binaryMinimumMatchBytes(re.Sub[0])
	case binarysyntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			minimum := binaryMinimumMatchBytes(sub)
			if minimum > int(^uint(0)>>1)-total {
				return 0
			}
			total += minimum
		}
		return total
	case binarysyntax.OpAlternate:
		if len(re.Sub) == 0 {
			return 0
		}
		minimum := binaryMinimumMatchBytes(re.Sub[0])
		for _, sub := range re.Sub[1:] {
			if current := binaryMinimumMatchBytes(sub); current < minimum {
				minimum = current
			}
		}
		return minimum
	case binarysyntax.OpRepeat:
		if re.Min == 0 || len(re.Sub) != 1 {
			return 0
		}
		minimum := binaryMinimumMatchBytes(re.Sub[0])
		if minimum != 0 && re.Min > int(^uint(0)>>1)/minimum {
			return 0
		}
		return re.Min * minimum
	default:
		return 0
	}
}
