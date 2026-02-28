// Package validator wraps go-playground/validator to provide a shared,
// reusable validation instance with custom tag registrations.
package validator

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/go-playground/validator/v10"
)

var (
	instance *validator.Validate
	once     sync.Once
)

func initInstance() {
	instance = validator.New()
}

func Validate(s any) error {
	once.Do(initInstance)
	err := instance.Struct(s)
	if err == nil {
		return nil
	}
	if ve, ok := err.(validator.ValidationErrors); ok {
		validationErrs := ValidationErrors{
			Fields: make([]FieldError, 0, len(ve)),
		}
		for _, e := range ve {
			validationErrs.Fields = append(validationErrs.Fields, FieldError{
				Field: e.Field(),
				Tag:   e.Tag(),
				Value: fmt.Sprintf("%v", e.Value()),
			})
		}
		return validationErrs
	}
	return err
}

type ValidationErrors struct {
	Fields []FieldError
}

type FieldError struct {
	Field string `json:"field"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

func (v ValidationErrors) Error() string {
	if len(v.Fields) == 0 {
		return "validation failed"
	}
	if len(v.Fields) == 1 {
		return fmt.Sprintf("%s: %s (value: %s)", v.Fields[0].Field, v.Fields[0].Tag, v.Fields[0].Value)
	}
	b, _ := json.Marshal(v.Fields)
	return string(b)
}
