// Package id provides identifier generation. Time-sortable UUID v7 for primary keys.
package id

import "github.com/google/uuid"

// New returns a new UUID v7 as a string (time-sortable).
// Use for primary keys and external IDs where ordering by creation time is useful.
func New() string {
	return uuid.Must(uuid.NewV7()).String()
}
