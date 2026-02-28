package pagination

const (
	DefaultPage     = 1
	DefaultLimit    = 20
	DefaultSortOrder = "asc"
	MaxLimit        = 100
)

type Params struct {
	Page      int
	Limit     int
	SortBy    string
	SortOrder string
}

type Meta struct {
	Page       int
	Limit      int
	TotalItems int
	TotalPages int
}

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
	if sortOrder == "" {
		sortOrder = DefaultSortOrder
	}
	return Params{
		Page:      page,
		Limit:     limit,
		SortBy:    sortBy,
		SortOrder: sortOrder,
	}
}

func NewMeta(params Params, totalItems int) Meta {
	totalPages := totalItems / params.Limit
	if totalItems%params.Limit > 0 {
		totalPages++
	}
	if totalPages < 1 {
		totalPages = 1
	}
	return Meta{
		Page:       params.Page,
		Limit:      params.Limit,
		TotalItems: totalItems,
		TotalPages: totalPages,
	}
}

func (p Params) Offset() int {
	return (p.Page - 1) * p.Limit
}
