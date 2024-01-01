// Copyright (C) 2019 Nicola Murino
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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package common

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"sync"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	// DefaultTLSKeyPaidID defines the id to use for non-binding specific key pairs
	DefaultTLSKeyPaidID = "default"
	pemCRLType          = "X509 CRL"
)

var (
	pemCRLPrefix = []byte("-----BEGIN X509 CRL")
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
	monitorList       []string
	certs             map[string]*tls.Certificate
	certsInfo         map[string]fs.FileInfo
	rootCAs           *x509.CertPool
	crls              []*x509.RevocationList
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
			logger.Error(m.logSender, "", "unable to load X509 key pair, cert file %q key file %q error: %v",
				keyPair.Cert, keyPair.Key, err)
			return err
		}
		if _, ok := certs[keyPair.ID]; ok {
			logger.Error(m.logSender, "", "TLS certificate with id %q is duplicated", keyPair.ID)
			return fmt.Errorf("TLS certificate with id %q is duplicated", keyPair.ID)
		}
		logger.Debug(m.logSender, "", "TLS certificate %q successfully loaded, id %v", keyPair.Cert, keyPair.ID)
		certs[keyPair.ID] = &newCert
		if !util.Contains(m.monitorList, keyPair.Cert) {
			m.monitorList = append(m.monitorList, keyPair.Cert)
		}
	}

	m.Lock()
	defer m.Unlock()

	m.certs = certs
	return nil
}

// HasCertificate returns true if there is a certificate for the specified certID
func (m *CertManager) HasCertificate(certID string) bool {
	m.RLock()
	defer m.RUnlock()

	_, ok := m.certs[certID]
	return ok
}

// GetCertificateFunc returns the loaded certificate
func (m *CertManager) GetCertificateFunc(certID string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		m.RLock()
		defer m.RUnlock()

		val, ok := m.certs[certID]
		if !ok {
			logger.Error(m.logSender, "", "no certificate for id %s", certID)
			return nil, fmt.Errorf("no certificate for id %s", certID)
		}

		return val, nil
	}
}

// IsRevoked returns true if the specified certificate has been revoked
func (m *CertManager) IsRevoked(crt *x509.Certificate, caCrt *x509.Certificate) bool {
	m.RLock()
	defer m.RUnlock()

	if crt == nil || caCrt == nil {
		logger.Error(m.logSender, "", "unable to verify crt %v, ca crt %v", crt, caCrt)
		return len(m.crls) > 0
	}

	for _, crl := range m.crls {
		if crl.CheckSignatureFrom(caCrt) == nil {
			for _, rc := range crl.RevokedCertificateEntries {
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

	var crls []*x509.RevocationList

	for _, revocationList := range m.caRevocationLists {
		if !util.IsFileInputValid(revocationList) {
			return fmt.Errorf("invalid root CA revocation list %q", revocationList)
		}
		if revocationList != "" && !filepath.IsAbs(revocationList) {
			revocationList = filepath.Join(m.configDir, revocationList)
		}
		crlBytes, err := os.ReadFile(revocationList)
		if err != nil {
			logger.Error(m.logSender, "", "unable to read revocation list %q", revocationList)
			return err
		}
		if bytes.HasPrefix(crlBytes, pemCRLPrefix) {
			block, _ := pem.Decode(crlBytes)
			if block != nil && block.Type == pemCRLType {
				crlBytes = block.Bytes
			}
		}
		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			logger.Error(m.logSender, "", "unable to parse revocation list %q", revocationList)
			return err
		}

		logger.Debug(m.logSender, "", "CRL %q successfully loaded", revocationList)
		crls = append(crls, crl)
		if !util.Contains(m.monitorList, revocationList) {
			m.monitorList = append(m.monitorList, revocationList)
		}
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
			return fmt.Errorf("invalid root CA certificate %q", rootCA)
		}
		if rootCA != "" && !filepath.IsAbs(rootCA) {
			rootCA = filepath.Join(m.configDir, rootCA)
		}
		crt, err := os.ReadFile(rootCA)
		if err != nil {
			logger.Error(m.logSender, "", "unable to read root CA from file %q: %v", rootCA, err)
			return err
		}
		if rootCAs.AppendCertsFromPEM(crt) {
			logger.Debug(m.logSender, "", "TLS certificate authority %q successfully loaded", rootCA)
		} else {
			err := fmt.Errorf("unable to load TLS certificate authority %q", rootCA)
			logger.Error(m.logSender, "", "%v", err)
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

func (m *CertManager) monitor() {
	certsInfo := make(map[string]fs.FileInfo)

	for _, crt := range m.monitorList {
		info, err := os.Stat(crt)
		if err != nil {
			logger.Warn(m.logSender, "", "unable to stat certificate to monitor %q: %v", crt, err)
			return
		}
		certsInfo[crt] = info
	}

	m.Lock()

	isChanged := false
	for k, oldInfo := range m.certsInfo {
		newInfo, ok := certsInfo[k]
		if ok {
			if newInfo.Size() != oldInfo.Size() || newInfo.ModTime() != oldInfo.ModTime() {
				logger.Debug(m.logSender, "", "change detected for certificate %q, reload required", k)
				isChanged = true
			}
		}
	}
	m.certsInfo = certsInfo

	m.Unlock()

	if isChanged {
		m.Reload() //nolint:errcheck
	}
}

// NewCertManager creates a new certificate manager
func NewCertManager(keyPairs []TLSKeyPair, configDir, logSender string) (*CertManager, error) {
	manager := &CertManager{
		keyPairs:  keyPairs,
		configDir: configDir,
		logSender: logSender,
		certs:     make(map[string]*tls.Certificate),
		certsInfo: make(map[string]fs.FileInfo),
	}
	err := manager.loadCertificates()
	if err != nil {
		return nil, err
	}
	randSecs := rand.Intn(59)
	manager.monitor()
	if eventScheduler != nil {
		_, err = eventScheduler.AddFunc(fmt.Sprintf("@every 8h0m%ds", randSecs), manager.monitor)
	}
	return manager, err
}
