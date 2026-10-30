// Package pagination provides generic pagination and sort parameters.
// Protocol-agnostic: pure data structs and constructors.
// Filters are module-specific; each API defines its own filter extraction.
package pagination

import (
	"strconv"
	"strings"
)

const (
	DefaultPage  = 1
	DefaultLimit = 20
	MaxLimit     = 100
	SortAsc      = "asc"
	SortDesc     = "desc"
)

// Params holds universal pagination and sort parameters.
// Module-specific filters are defined in each module's dto.
type Params struct {
	Page      int
	Limit     int
	Offset    int
	SortBy    string
	SortOrder string
}

// Meta holds complete pagination metadata for API responses.
// Frontend can show "Showing From to To of TotalItems records".
type Meta struct {
	TotalItems  int  `json:"total_items"`
	TotalPages  int  `json:"total_pages"`
	Page        int  `json:"page"`
	Limit       int  `json:"limit"`
	From        int  `json:"from"`
	To          int  `json:"to"`
	HasNext     bool `json:"has_next"`
	HasPrevious bool `json:"has_previous"`
}

// NewParams builds Params from raw values. Clamps page/limit and normalizes sort order.
// Transport layers extract query params (page, limit, sort_by, sort_order) and call this.
func NewParams(page, limit int, sortBy, sortOrder string) Params {
	if page < 1 {
		page = DefaultPage
	}
	if limit < 1 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	order := strings.ToLower(strings.TrimSpace(sortOrder))
	if order != SortAsc && order != SortDesc {
		order = SortDesc
	}
	return Params{
		Page:      page,
		Limit:     limit,
		Offset:    (page - 1) * limit,
		SortBy:    strings.TrimSpace(sortBy),
		SortOrder: order,
	}
}

// ParsePage parses a page number from a string (e.g. query param). Returns DefaultPage if invalid.
func ParsePage(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 {
		return DefaultPage
	}
	return n
}

// ParseLimit parses a limit from a string. Returns DefaultLimit if invalid, caps at MaxLimit.
func ParseLimit(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 {
		return DefaultLimit
	}
	if n > MaxLimit {
		return MaxLimit
	}
	return n
}

// NewMeta builds pagination metadata for responses.
// total is the count of all matching records across all pages.
func NewMeta(params Params, total int) *Meta {
	totalPages := 0
	if total > 0 {
		totalPages = total / params.Limit
		if total%params.Limit > 0 {
			totalPages++
		}
	}

	from, to := 0, 0
	if total > 0 {
		from = params.Offset + 1
		to = params.Offset + params.Limit
		if to > total {
			to = total
		}
	}

	return &Meta{
		TotalItems:  total,
		TotalPages:  totalPages,
		Page:        params.Page,
		Limit:       params.Limit,
		From:        from,
		To:          to,
		HasNext:     params.Page < totalPages,
		HasPrevious: params.Page > 1,
	}
}
