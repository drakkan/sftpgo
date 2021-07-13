package kms

// BaseSecret defines the base struct shared among all the secret providers
type BaseSecret struct {
	Status         SecretStatus `json:"status,omitempty"`
	Payload        string       `json:"payload,omitempty"`
	Key            string       `json:"key,omitempty"`
	AdditionalData string       `json:"additional_data,omitempty"`
	// 1 means encrypted using a master key
	Mode int `json:"mode,omitempty"`
}

func (s *BaseSecret) GetStatus() SecretStatus {
	return s.Status
}

func (s *BaseSecret) GetPayload() string {
	return s.Payload
}

func (s *BaseSecret) GetKey() string {
	return s.Key
}

func (s *BaseSecret) GetMode() int {
	return s.Mode
}

func (s *BaseSecret) GetAdditionalData() string {
	return s.AdditionalData
}

func (s *BaseSecret) SetKey(value string) {
	s.Key = value
}

func (s *BaseSecret) SetAdditionalData(value string) {
	s.AdditionalData = value
}

func (s *BaseSecret) SetStatus(value SecretStatus) {
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
