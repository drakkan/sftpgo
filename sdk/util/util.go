// Package util provides some common utility methods
package util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// IsStringInSlice searches a string in a slice and returns true if the string is found
func IsStringInSlice(obj string, list []string) bool {
	for i := 0; i < len(list); i++ {
		if list[i] == obj {
			return true
		}
	}
	return false
}

// EncodeTLSCertToPem returns the specified certificate PEM encoded.
// This can be verified using openssl x509 -in cert.crt  -text -noout
func EncodeTLSCertToPem(tlsCert *x509.Certificate) (string, error) {
	if len(tlsCert.Raw) == 0 {
		return "", errors.New("invalid x509 certificate, no der contents")
	}
	publicKeyBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tlsCert.Raw,
	}
	return string(pem.EncodeToMemory(&publicKeyBlock)), nil
}
