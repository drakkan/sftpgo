// Copyright (C) 2019-2022  Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package util

import (
	"fmt"
)

const (
	templateLoadErrorHints = "Try setting the absolute templates path in your configuration file " +
		"or specifying the config directory adding the `-c` flag to the serve options. For example: " +
		"sftpgo serve -c \"<path to dir containing the default config file and templates directory>\""
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
