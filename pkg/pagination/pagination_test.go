package pagination

import (
	"testing"
)

func TestNewParams(t *testing.T) {
	p := NewParams(0, 0, "", "")
	if p.Page != DefaultPage {
		t.Errorf("Page = %d, want %d", p.Page, DefaultPage)
	}
	if p.Limit != DefaultLimit {
		t.Errorf("Limit = %d, want %d", p.Limit, DefaultLimit)
	}
	if p.Offset != 0 {
		t.Errorf("Offset = %d, want 0", p.Offset)
	}
	p2 := NewParams(2, 10, "name", "asc")
	if p2.Offset != 10 {
		t.Errorf("Offset = %d, want 10", p2.Offset)
	}
	if p2.SortOrder != SortAsc {
		t.Errorf("SortOrder = %s, want %s", p2.SortOrder, SortAsc)
	}
	// over max limit
	p3 := NewParams(1, 200, "", "")
	if p3.Limit != MaxLimit {
		t.Errorf("Limit = %d, want %d", p3.Limit, MaxLimit)
	}
}

func TestParsePage(t *testing.T) {
	if got := ParsePage(""); got != DefaultPage {
		t.Errorf("ParsePage(\"\") = %d", got)
	}
	if got := ParsePage("3"); got != 3 {
		t.Errorf("ParsePage(\"3\") = %d", got)
	}
	if got := ParsePage("0"); got != DefaultPage {
		t.Errorf("ParsePage(\"0\") = %d", got)
	}
}

func TestParseLimit(t *testing.T) {
	if got := ParseLimit(""); got != DefaultLimit {
		t.Errorf("ParseLimit(\"\") = %d", got)
	}
	if got := ParseLimit("50"); got != 50 {
		t.Errorf("ParseLimit(\"50\") = %d", got)
	}
	if got := ParseLimit("999"); got != MaxLimit {
		t.Errorf("ParseLimit(\"999\") = %d, want MaxLimit", got)
	}
}

func TestNewMeta(t *testing.T) {
	params := Params{Page: 1, Limit: 10, Offset: 0}
	meta := NewMeta(params, 25)
	if meta.TotalItems != 25 {
		t.Errorf("TotalItems = %d", meta.TotalItems)
	}
	if meta.TotalPages != 3 {
		t.Errorf("TotalPages = %d", meta.TotalPages)
	}
	if meta.From != 1 || meta.To != 10 {
		t.Errorf("From=%d To=%d", meta.From, meta.To)
	}
	if !meta.HasNext || meta.HasPrevious {
		t.Errorf("HasNext=%v HasPrevious=%v", meta.HasNext, meta.HasPrevious)
	}
	// page 2
	params2 := Params{Page: 2, Limit: 10, Offset: 10}
	meta2 := NewMeta(params2, 25)
	if meta2.From != 11 || meta2.To != 20 {
		t.Errorf("From=%d To=%d", meta2.From, meta2.To)
	}
}
