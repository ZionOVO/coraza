// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo && !coraza.no_memoize

package memoize

import "sync"

type entry struct {
	value   any
	mu      sync.Mutex
	owners  map[uint64]struct{}
	deleted bool
}

var cache sync.Map // key -> *entry

// Memoizer caches expensive function calls with per-owner tracking.
// TinyGo variant without singleflight.
type Memoizer struct {
	ownerID uint64
}

// NewMemoizer creates a Memoizer that tracks cached entries under the given owner ID.
func NewMemoizer(ownerID uint64) *Memoizer {
	return &Memoizer{ownerID: ownerID}
}

func (m *Memoizer) addOwner(e *entry) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.deleted {
		return false
	}
	e.owners[m.ownerID] = struct{}{}
	return true
}

// Do returns a cached value for key, or calls fn and caches the result.
func (m *Memoizer) Do(key string, fn func() (any, error)) (any, error) {
	for {
		if v, ok := cache.Load(key); ok {
			e := v.(*entry)
			if m.addOwner(e) {
				return e.value, nil
			}
		}

		data, err := fn()
		if err != nil {
			return data, err
		}
		candidate := &entry{
			value:  data,
			owners: map[uint64]struct{}{m.ownerID: {}},
		}
		actual, loaded := cache.LoadOrStore(key, candidate)
		if !loaded {
			return data, nil
		}
		e := actual.(*entry)
		if m.addOwner(e) {
			return e.value, nil
		}
		cache.CompareAndDelete(key, e)
	}
}

// Release removes ownerID from all cached entries, deleting entries with no remaining owners.
//
// Deletions are deferred until after Range completes because TinyGo's sync.Map
// holds its internal lock for the entire Range call, so calling Delete inside
// the callback would deadlock.
func Release(ownerID uint64) {
	type pendingDelete struct {
		key   any
		entry *entry
	}
	var toDelete []pendingDelete
	cache.Range(func(key, value any) bool {
		e := value.(*entry)
		e.mu.Lock()
		delete(e.owners, ownerID)
		if len(e.owners) == 0 {
			e.deleted = true
			toDelete = append(toDelete, pendingDelete{key: key, entry: e})
		}
		e.mu.Unlock()
		return true
	})
	for _, pending := range toDelete {
		cache.CompareAndDelete(pending.key, pending.entry)
	}
}

// Reset clears the entire cache. Intended for testing.
//
// Keys are collected first and deleted after Range returns to avoid deadlocking
// on TinyGo's mutex-based sync.Map (see Release comment).
func Reset() {
	var keys []any
	cache.Range(func(key, _ any) bool {
		keys = append(keys, key)
		return true
	})
	for _, key := range keys {
		cache.Delete(key)
	}
}
