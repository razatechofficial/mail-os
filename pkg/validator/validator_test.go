package validator

import (
	"testing"
)

func TestValidate(t *testing.T) {
	type valid struct {
		Name string `json:"name" validate:"required"`
	}
	v := valid{Name: "ok"}
	if errs := Validate(v); errs != nil {
		t.Errorf("Validate(valid) = %v, want nil", errs)
	}
	v2 := valid{}
	errs := Validate(v2)
	if errs == nil || len(errs) == 0 {
		t.Fatal("Validate(empty name) want field errors")
	}
	if errs[0].Field != "Name" && errs[0].Field != "name" {
		t.Errorf("Field = %q", errs[0].Field)
	}
}

func TestValidate_optional(t *testing.T) {
	type optional struct {
		Email string `json:"email" validate:"omitempty,email"`
	}
	if errs := Validate(optional{}); errs != nil {
		t.Errorf("Validate(empty optional) = %v", errs)
	}
	if errs := Validate(optional{Email: "bad"}); errs == nil {
		t.Error("Validate(bad email) want errors")
	}
	if errs := Validate(optional{Email: "a@b.co"}); errs != nil {
		t.Errorf("Validate(good email) = %v", errs)
	}
}
