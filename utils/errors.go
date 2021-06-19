package utils

import "fmt"

// ValidationError raised if input data is not valid
type ValidationError struct {
	err string
}

// Validation error details
func (e *ValidationError) Error() string {
	return fmt.Sprintf("Validation error: %s", e.err)
}

// NewValidationError returns a validation errors
func NewValidationError(error string) *ValidationError {
	return &ValidationError{
		err: error,
	}
}
