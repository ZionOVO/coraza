// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.no_memoize

package memoize

import (
	"sync"

	"golang.org/x/sync/singleflight"
)

type entry struct {
	value   any
	mu      sync.Mutex
	owners  map[uint64]struct{}
	deleted bool
}

var (
	cache sync.Map // key -> *entry
	group singleflight.Group
)

// Memoizer caches expensive function calls with per-owner tracking.
type Memoizer struct {
	ownerID uint64
}

// NewMemoizer creates a Memoizer that tracks cached entries under the given owner ID.
func NewMemoizer(ownerID uint64) *Memoizer {
	return &Memoizer{ownerID: ownerID}
}

// addOwner attempts to register the ownerID on the entry.
// Returns false if the entry has been marked as deleted.
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
// Only one execution is in-flight for a given key at a time.
func (m *Memoizer) Do(key string, fn func() (any, error)) (any, error) {
	for {
		// Fast path: check cache
		if v, ok := cache.Load(key); ok {
			e := v.(*entry)
			if m.addOwner(e) {
				return e.value, nil
			}
			// Entry was deleted concurrently; fall through to slow path.
		}

		// Slow path: singleflight ensures only one compilation per key.
		result, err, _ := group.Do(key, func() (any, error) {
			// Double-check after acquiring singleflight.
			if v, ok := cache.Load(key); ok {
				e := v.(*entry)
				if m.addOwner(e) {
					return e, nil
				}
			}

			data, innerErr := fn()
			if innerErr != nil {
				return data, innerErr
			}
			candidate := &entry{
				value:  data,
				owners: map[uint64]struct{}{m.ownerID: {}},
			}
			for {
				actual, loaded := cache.LoadOrStore(key, candidate)
				if !loaded {
					return candidate, nil
				}
				e := actual.(*entry)
				if m.addOwner(e) {
					return e, nil
				}
				// Release marked this entry before removing it from the map.
				cache.CompareAndDelete(key, e)
			}
		})
		if err != nil {
			return result, err
		}

		// Every caller must own the exact entry whose value it returns. A
		// waiter can observe that entry after its compiling owner released it;
		// retry instead of registering the waiter on a concurrent replacement.
		e := result.(*entry)
		if m.addOwner(e) {
			return e.value, nil
		}
	}
}

// Release removes ownerID from all cached entries, deleting entries with no remaining owners.
func Release(ownerID uint64) {
	cache.Range(func(key, value any) bool {
		e := value.(*entry)
		releaseEntry(key, e, ownerID)
		return true
	})
}

func releaseEntry(key any, e *entry, ownerID uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.owners, ownerID)
	if len(e.owners) == 0 {
		e.deleted = true
		// A concurrent compiler may already have replaced a deleted entry.
		// Delete only the entry observed by Release so its replacement survives.
		cache.CompareAndDelete(key, e)
	}
}

// Reset clears the entire cache. Intended for testing.
func Reset() {
	cache.Range(func(key, _ any) bool {
		cache.Delete(key)
		return true
	})
}
