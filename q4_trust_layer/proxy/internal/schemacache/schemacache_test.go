package schemacache

import (
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func schema() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{"path": map[string]any{"type": "string"}},
		"required":   []any{"path"},
	}
}

func TestCompiledIsCachedPerDefHash(t *testing.T) {
	c := New()
	a, err := c.Compiled("sha256:a", schema())
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := c.Compiled("sha256:a", schema())
	if a != a2 {
		t.Fatal("same def_hash must return the same compiled schema")
	}
}

func BenchmarkValidate(b *testing.B) {
	sch, err := New().Compiled("sha256:a", schema())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(`{"path":"/x"}`))
		if err := sch.Validate(inst); err != nil {
			b.Fatal(err)
		}
	}
}
