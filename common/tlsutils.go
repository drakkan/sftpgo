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

package common

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

const (
	// DefaultTLSKeyPaidID defines the id to use for non-binding specific key pairs
	DefaultTLSKeyPaidID = "default"
)

// TLSKeyPair defines the paths and the unique identifier for a TLS key pair
type TLSKeyPair struct {
	Cert string
	Key  string
	ID   string
}

// CertManager defines a TLS certificate manager
type CertManager struct {
	keyPairs  []TLSKeyPair
	configDir string
	logSender string
	sync.RWMutex
	caCertificates    []string
	caRevocationLists []string
	certs             map[string]*tls.Certificate
	rootCAs           *x509.CertPool
	crls              []*pkix.CertificateList
}

// Reload tries to reload certificate and CRLs
func (m *CertManager) Reload() error {
	errCrt := m.loadCertificates()
	errCRLs := m.LoadCRLs()

	if errCrt != nil {
		return errCrt
	}
	return errCRLs
}

// LoadCertificates tries to load the configured x509 key pairs
func (m *CertManager) loadCertificates() error {
	if len(m.keyPairs) == 0 {
		return errors.New("no key pairs defined")
	}
	certs := make(map[string]*tls.Certificate)
	for _, keyPair := range m.keyPairs {
		if keyPair.ID == "" {
			return errors.New("TLS certificate without ID")
		}
		newCert, err := tls.LoadX509KeyPair(keyPair.Cert, keyPair.Key)
		if err != nil {
			logger.Warn(m.logSender, "", "unable to load X509 key pair, cert file %#v key file %#v error: %v",
				keyPair.Cert, keyPair.Key, err)
			return err
		}
		if _, ok := certs[keyPair.ID]; ok {
			return fmt.Errorf("TLS certificate with id %#v is duplicated", keyPair.ID)
		}
		logger.Debug(m.logSender, "", "TLS certificate %#v successfully loaded, id %v", keyPair.Cert, keyPair.ID)
		certs[keyPair.ID] = &newCert
	}

	m.Lock()
	defer m.Unlock()

	m.certs = certs
	return nil
}

// GetCertificateFunc returns the loaded certificate
func (m *CertManager) GetCertificateFunc(certID string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		m.RLock()
		defer m.RUnlock()

		val, ok := m.certs[certID]
		if !ok {
			return nil, fmt.Errorf("no certificate for id %v", certID)
		}

		return val, nil
	}
}

// IsRevoked returns true if the specified certificate has been revoked
func (m *CertManager) IsRevoked(crt *x509.Certificate, caCrt *x509.Certificate) bool {
	m.RLock()
	defer m.RUnlock()

	if crt == nil || caCrt == nil {
		logger.Warn(m.logSender, "", "unable to verify crt %v ca crt %v", crt, caCrt)
		return len(m.crls) > 0
	}

	for _, crl := range m.crls {
		if !crl.HasExpired(time.Now()) && caCrt.CheckCRLSignature(crl) == nil {
			for _, rc := range crl.TBSCertList.RevokedCertificates {
				if rc.SerialNumber.Cmp(crt.SerialNumber) == 0 {
					return true
				}
			}
		}
	}

	return false
}

// LoadCRLs tries to load certificate revocation lists from the given paths
func (m *CertManager) LoadCRLs() error {
	if len(m.caRevocationLists) == 0 {
		return nil
	}

	var crls []*pkix.CertificateList

	for _, revocationList := range m.caRevocationLists {
		if !util.IsFileInputValid(revocationList) {
			return fmt.Errorf("invalid root CA revocation list %#v", revocationList)
		}
		if revocationList != "" && !filepath.IsAbs(revocationList) {
			revocationList = filepath.Join(m.configDir, revocationList)
		}
		crlBytes, err := os.ReadFile(revocationList)
		if err != nil {
			logger.Warn(m.logSender, "unable to read revocation list %#v", revocationList)
			return err
		}
		crl, err := x509.ParseCRL(crlBytes)
		if err != nil {
			logger.Warn(m.logSender, "unable to parse revocation list %#v", revocationList)
			return err
		}

		logger.Debug(m.logSender, "", "CRL %#v successfully loaded", revocationList)
		crls = append(crls, crl)
	}

	m.Lock()
	defer m.Unlock()

	m.crls = crls

	return nil
}

// GetRootCAs returns the set of root certificate authorities that servers
// use if required to verify a client certificate
func (m *CertManager) GetRootCAs() *x509.CertPool {
	m.RLock()
	defer m.RUnlock()

	return m.rootCAs
}

// LoadRootCAs tries to load root CA certificate authorities from the given paths
func (m *CertManager) LoadRootCAs() error {
	if len(m.caCertificates) == 0 {
		return nil
	}

	rootCAs := x509.NewCertPool()

	for _, rootCA := range m.caCertificates {
		if !util.IsFileInputValid(rootCA) {
			return fmt.Errorf("invalid root CA certificate %#v", rootCA)
		}
		if rootCA != "" && !filepath.IsAbs(rootCA) {
			rootCA = filepath.Join(m.configDir, rootCA)
		}
		crt, err := os.ReadFile(rootCA)
		if err != nil {
			return err
		}
		if rootCAs.AppendCertsFromPEM(crt) {
			logger.Debug(m.logSender, "", "TLS certificate authority %#v successfully loaded", rootCA)
		} else {
			err := fmt.Errorf("unable to load TLS certificate authority %#v", rootCA)
			logger.Warn(m.logSender, "", "%v", err)
			return err
		}
	}

	m.Lock()
	defer m.Unlock()

	m.rootCAs = rootCAs
	return nil
}

// SetCACertificates sets the root CA authorities file paths.
// This should not be changed at runtime
func (m *CertManager) SetCACertificates(caCertificates []string) {
	m.caCertificates = util.RemoveDuplicates(caCertificates, true)
}

// SetCARevocationLists sets the CA revocation lists file paths.
// This should not be changed at runtime
func (m *CertManager) SetCARevocationLists(caRevocationLists []string) {
	m.caRevocationLists = util.RemoveDuplicates(caRevocationLists, true)
}

// NewCertManager creates a new certificate manager
func NewCertManager(keyPairs []TLSKeyPair, configDir, logSender string) (*CertManager, error) {
	manager := &CertManager{
		keyPairs:  keyPairs,
		certs:     make(map[string]*tls.Certificate),
		configDir: configDir,
		logSender: logSender,
	}
	err := manager.loadCertificates()
	if err != nil {
		return nil, err
	}
	return manager, nil
}
