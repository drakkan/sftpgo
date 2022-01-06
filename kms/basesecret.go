package kms

import (
	sdkkms "github.com/sftpgo/sdk/kms"
)

// BaseSecret defines the base struct shared among all the secret providers
type BaseSecret struct {
	Status         sdkkms.SecretStatus `json:"status,omitempty"`
	Payload        string              `json:"payload,omitempty"`
	Key            string              `json:"key,omitempty"`
	AdditionalData string              `json:"additional_data,omitempty"`
	// 1 means encrypted using a master key
	Mode int `json:"mode,omitempty"`
}

// GetStatus returns the secret's status
func (s *BaseSecret) GetStatus() sdkkms.SecretStatus {
	return s.Status
}

// GetPayload returns the secret's payload
func (s *BaseSecret) GetPayload() string {
	return s.Payload
}

// GetKey returns the secret's key
func (s *BaseSecret) GetKey() string {
	return s.Key
}

// GetMode returns the encryption mode
func (s *BaseSecret) GetMode() int {
	return s.Mode
}

// GetAdditionalData returns the secret's additional data
func (s *BaseSecret) GetAdditionalData() string {
	return s.AdditionalData
}

// SetKey sets the secret's key
func (s *BaseSecret) SetKey(value string) {
	s.Key = value
}

// SetAdditionalData sets the secret's additional data
func (s *BaseSecret) SetAdditionalData(value string) {
	s.AdditionalData = value
}

// SetStatus sets the secret's status
func (s *BaseSecret) SetStatus(value sdkkms.SecretStatus) {
	s.Status = value
}

func (s *BaseSecret) isEmpty() bool {
	if s.Status != "" {
		return false
	}
	if s.Payload != "" {
		return false
	}
	if s.Key != "" {
		return false
	}
	if s.AdditionalData != "" {
		return false
	}
	return true
}
