package id

import (
	"testing"

	"github.com/google/uuid"
)

func TestNew(t *testing.T) {
	s := New()
	if s == "" {
		t.Fatal("New() returned empty string")
	}
	_, err := uuid.Parse(s)
	if err != nil {
		t.Errorf("New() = %q is not valid UUID: %v", s, err)
	}
	// uniqueness
	m := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s := New()
		if m[s] {
			t.Errorf("duplicate id %q", s)
		}
		m[s] = true
	}
}
