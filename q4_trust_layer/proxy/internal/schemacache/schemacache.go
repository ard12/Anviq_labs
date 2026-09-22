// Package schemacache compiles a tool's inputSchema once per def_hash and
// caches the result. Compilation happens on the tools/list path (rare); the
// hot tools/call path only ever does a map lookup + Validate. See
// DESIGN.md §6 (latency budget) and DECISIONS.md ("hash-only hot path vs
// full diff").
package schemacache

import (
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Cache is safe for concurrent use. The underlying jsonschema.Compiler is not
// safe for concurrent Compile calls, so compilation (the rare path) is
// serialized with a mutex; reads from the sync.Map (the hot path) are lock-free.
type Cache struct {
	mu       sync.Mutex
	compiler *jsonschema.Compiler
	schemas  sync.Map // def_hash (string) -> *jsonschema.Schema
}

func New() *Cache {
	return &Cache{compiler: jsonschema.NewCompiler()}
}

// Compiled returns the compiled schema for defHash, compiling and caching it
// on first use. inputSchema is the raw (already-normalized-for-hashing, but
// here used as-is) JSON Schema object for the tool's arguments.
func (c *Cache) Compiled(defHash string, inputSchema map[string]any) (*jsonschema.Schema, error) {
	if v, ok := c.schemas.Load(defHash); ok {
		return v.(*jsonschema.Schema), nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check under the lock: another goroutine may have compiled it while we waited.
	if v, ok := c.schemas.Load(defHash); ok {
		return v.(*jsonschema.Schema), nil
	}
	url := "mem://tool-schema/" + defHash
	doc := inputSchema
	if doc == nil {
		doc = map[string]any{}
	}
	if err := c.compiler.AddResource(url, doc); err != nil {
		return nil, fmt.Errorf("schemacache: AddResource %s: %w", defHash, err)
	}
	sch, err := c.compiler.Compile(url)
	if err != nil {
		return nil, fmt.Errorf("schemacache: Compile %s: %w", defHash, err)
	}
	c.schemas.Store(defHash, sch)
	return sch, nil
}
