package quarantine

import "testing"

func TestReplaceAndContains(t *testing.T) {
	s := NewSet()
	if s.Contains("fs", "read_file") {
		t.Fatal("new set must be empty")
	}
	s.Replace([]Entry{{Server: "fs", Tool: "read_file"}})
	if !s.Contains("fs", "read_file") || s.Contains("fs", "other") || s.Contains("mail", "read_file") {
		t.Fatal("Contains must match exact (server, tool) only")
	}
	s.Replace(nil)
	if s.Contains("fs", "read_file") {
		t.Fatal("Replace swaps the whole snapshot")
	}
}

func BenchmarkContains(b *testing.B) {
	s := NewSet()
	s.Replace([]Entry{{Server: "fs", Tool: "a"}, {Server: "fs", Tool: "b"}})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Contains("fs", "read_file")
	}
}
