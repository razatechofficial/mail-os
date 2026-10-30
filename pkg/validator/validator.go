// Package validator provides structured request validation.
// Protocol-agnostic: wraps go-playground/validator and returns []FieldError.
// Transport layers convert FieldError to their response format.
package validator

import (
	"errors"
	"reflect"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
)

// FieldError is a single field validation failure.
// HTTP/gRPC layers map this to their error response shape.
type FieldError struct {
	Field   string
	Code    string // the failed rule: required, email, max...
	Message string
}

var (
	instance *validator.Validate
	once     sync.Once
)

// get returns the singleton validator instance.
// Initialized once — thread safe via sync.Once.
func get() *validator.Validate {
	once.Do(func() {
		instance = validator.New()

		// use json tag name in errors instead of struct field name
		// so errors say "email" not "Email"
		instance.RegisterTagNameFunc(func(fld reflect.StructField) string {
			name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
			if name == "-" {
				return ""
			}
			return name
		})
	})
	return instance
}

// Validate validates a struct and returns field-level errors.
// Returns nil if validation passes.
// Returns []FieldError if validation fails; transport layers convert to response format.
func Validate(s any) []FieldError {
	err := get().Struct(s)
	if err == nil {
		return nil
	}

	var validationErrors validator.ValidationErrors
	if !errors.As(err, &validationErrors) {
		return nil
	}

	fieldErrors := make([]FieldError, 0, len(validationErrors))
	for _, e := range validationErrors {
		fieldErrors = append(fieldErrors, FieldError{
			Field:   e.Field(),
			Code:    e.Tag(),
			Message: fieldMessage(e),
		})
	}
	return fieldErrors
}

// fieldMessage converts a validator error into a human-readable message.
func fieldMessage(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return e.Field() + " is required"
	case "email":
		return "must be a valid email address"
	case "min":
		return e.Field() + " must be at least " + e.Param() + " characters"
	case "max":
		return e.Field() + " must be at most " + e.Param() + " characters"
	case "oneof":
		return e.Field() + " must be one of: " + e.Param()
	case "url":
		return "must be a valid URL"
	case "uuid":
		return e.Field() + " must be a valid UUID"
	case "numeric":
		return e.Field() + " must be a number"
	case "alphanum":
		return e.Field() + " must contain only letters and numbers"
	case "gte":
		return e.Field() + " must be greater than or equal to " + e.Param()
	case "lte":
		return e.Field() + " must be less than or equal to " + e.Param()
	case "len":
		return e.Field() + " must be exactly " + e.Param() + " characters"
	default:
		return e.Field() + " is invalid"
	}
}
