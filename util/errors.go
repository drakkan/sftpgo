package util

import (
	"fmt"
)

// ValidationError raised if input data is not valid
type ValidationError struct {
	err string
}

// Validation error details
func (e *ValidationError) Error() string {
	return fmt.Sprintf("Validation error: %s", e.err)
}

// GetErrorString returns the unmodified error string
func (e *ValidationError) GetErrorString() string {
	return e.err
}

// NewValidationError returns a validation errors
func NewValidationError(error string) *ValidationError {
	return &ValidationError{
		err: error,
	}
}

// RecordNotFoundError raised if a requested object is not found
type RecordNotFoundError struct {
	err string
}

func (e *RecordNotFoundError) Error() string {
	return fmt.Sprintf("not found: %s", e.err)
}

// NewRecordNotFoundError returns a not found error
func NewRecordNotFoundError(error string) *RecordNotFoundError {
	return &RecordNotFoundError{
		err: error,
	}
}

// MethodDisabledError raised if a method is disabled in config file.
// For example, if user management is disabled, this error is raised
// every time a user operation is done using the REST API
type MethodDisabledError struct {
	err string
}

// Method disabled error details
func (e *MethodDisabledError) Error() string {
	return fmt.Sprintf("Method disabled error: %s", e.err)
}

// NewMethodDisabledError returns a method disabled error
func NewMethodDisabledError(error string) *MethodDisabledError {
	return &MethodDisabledError{
		err: error,
	}
}

// GenericError raised for not well categorized error
type GenericError struct {
	err string
}

func (e *GenericError) Error() string {
	return e.err
}

// NewGenericError returns a generic error
func NewGenericError(error string) *GenericError {
	return &GenericError{
		err: error,
	}
}
