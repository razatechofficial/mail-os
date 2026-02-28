package errors

import (
	stderrors "errors"
)

const (
	grpcInvalidArgument  = 3
	grpcDeadlineExceeded = 4
	grpcNotFound        = 5
	grpcAlreadyExists   = 6
	grpcPermissionDenied = 7
	grpcResourceExhausted = 8
	grpcInternal        = 13
	grpcUnauthenticated = 16
)

var (
	ErrNotFound       = &AppError{Code: "NOT_FOUND", Message: "resource not found", HTTPStatus: 404, GRPCCode: grpcNotFound}
	ErrAlreadyExists  = &AppError{Code: "ALREADY_EXISTS", Message: "resource already exists", HTTPStatus: 409, GRPCCode: grpcAlreadyExists}
	ErrUnauthorized   = &AppError{Code: "UNAUTHORIZED", Message: "unauthorized", HTTPStatus: 401, GRPCCode: grpcUnauthenticated}
	ErrForbidden      = &AppError{Code: "FORBIDDEN", Message: "forbidden", HTTPStatus: 403, GRPCCode: grpcPermissionDenied}
	ErrBadRequest     = &AppError{Code: "BAD_REQUEST", Message: "bad request", HTTPStatus: 400, GRPCCode: grpcInvalidArgument}
	ErrConflict       = &AppError{Code: "CONFLICT", Message: "conflict", HTTPStatus: 409, GRPCCode: grpcAlreadyExists}
	ErrInternal       = &AppError{Code: "INTERNAL", Message: "internal server error", HTTPStatus: 500, GRPCCode: grpcInternal}
	ErrRateLimited    = &AppError{Code: "RATE_LIMITED", Message: "rate limited", HTTPStatus: 429, GRPCCode: grpcResourceExhausted}
	ErrValidation     = &AppError{Code: "VALIDATION", Message: "validation error", HTTPStatus: 422, GRPCCode: grpcInvalidArgument}
	ErrTimeout        = &AppError{Code: "TIMEOUT", Message: "request timeout", HTTPStatus: 504, GRPCCode: grpcDeadlineExceeded}
)

type AppError struct {
	Code       string
	Message    string
	HTTPStatus int
	GRPCCode   int
	Err        error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Err
}

func New(code, message string, httpStatus int) *AppError {
	return &AppError{Code: code, Message: message, HTTPStatus: httpStatus}
}

func Wrap(err error, code, message string, httpStatus int) *AppError {
	return &AppError{Code: code, Message: message, HTTPStatus: httpStatus, Err: err}
}

func NewNotFound(entity string) *AppError {
	return &AppError{Code: "NOT_FOUND", Message: entity + " not found", HTTPStatus: 404, GRPCCode: grpcNotFound}
}

func NewAlreadyExists(entity string) *AppError {
	return &AppError{Code: "ALREADY_EXISTS", Message: entity + " already exists", HTTPStatus: 409, GRPCCode: grpcAlreadyExists}
}

func NewBadRequest(message string) *AppError {
	return &AppError{Code: "BAD_REQUEST", Message: message, HTTPStatus: 400, GRPCCode: grpcInvalidArgument}
}

func NewUnauthorized(message string) *AppError {
	return &AppError{Code: "UNAUTHORIZED", Message: message, HTTPStatus: 401, GRPCCode: grpcUnauthenticated}
}

func NewForbidden(message string) *AppError {
	return &AppError{Code: "FORBIDDEN", Message: message, HTTPStatus: 403, GRPCCode: grpcPermissionDenied}
}

func NewInternal(message string) *AppError {
	return &AppError{Code: "INTERNAL", Message: message, HTTPStatus: 500, GRPCCode: grpcInternal}
}

func NewValidation(message string) *AppError {
	return &AppError{Code: "VALIDATION", Message: message, HTTPStatus: 422, GRPCCode: grpcInvalidArgument}
}

func NewRateLimited() *AppError {
	return &AppError{Code: "RATE_LIMITED", Message: "rate limited", HTTPStatus: 429, GRPCCode: grpcResourceExhausted}
}

func HTTPStatusFromError(err error) int {
	var appErr *AppError
	if As(err, &appErr) {
		return appErr.HTTPStatus
	}
	return 500
}

var Is = stderrors.Is
var As = stderrors.As
