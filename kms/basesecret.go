package kms

// baseSecret defines the base struct shared among all the secret providers
type baseSecret struct {
	Status         SecretStatus `json:"status,omitempty"`
	Payload        string       `json:"payload,omitempty"`
	Key            string       `json:"key,omitempty"`
	AdditionalData string       `json:"additional_data,omitempty"`
	// 1 means encrypted using a master key
	Mode int `json:"mode,omitempty"`
}

func (s *baseSecret) GetStatus() SecretStatus {
	return s.Status
}

func (s *baseSecret) GetPayload() string {
	return s.Payload
}

func (s *baseSecret) GetKey() string {
	return s.Key
}

func (s *baseSecret) GetMode() int {
	return s.Mode
}

func (s *baseSecret) GetAdditionalData() string {
	return s.AdditionalData
}

func (s *baseSecret) SetKey(value string) {
	s.Key = value
}

func (s *baseSecret) SetAdditionalData(value string) {
	s.AdditionalData = value
}

func (s *baseSecret) SetStatus(value SecretStatus) {
	s.Status = value
}

func (s *baseSecret) isEmpty() bool {
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
