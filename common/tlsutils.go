package common

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sync"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

// CertManager defines a TLS certificate manager
type CertManager struct {
	certPath string
	keyPath  string
	sync.RWMutex
	cert    *tls.Certificate
	rootCAs *x509.CertPool
}

// LoadCertificate loads the configured x509 key pair
func (m *CertManager) LoadCertificate(logSender string) error {
	newCert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		logger.Warn(logSender, "", "unable to load X509 key pair, cert file %#v key file %#v error: %v",
			m.certPath, m.keyPath, err)
		return err
	}
	logger.Debug(logSender, "", "TLS certificate %#v successfully loaded", m.certPath)
	m.Lock()
	defer m.Unlock()
	m.cert = &newCert
	return nil
}

// GetCertificateFunc returns the loaded certificate
func (m *CertManager) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		m.RLock()
		defer m.RUnlock()
		return m.cert, nil
	}
}

// GetRootCAs returns the set of root certificate authorities that servers
// use if required to verify a client certificate
func (m *CertManager) GetRootCAs() *x509.CertPool {
	return m.rootCAs
}

// LoadRootCAs tries to load root CA certificate authorities from the given paths
func (m *CertManager) LoadRootCAs(caCertificates []string, configDir string) error {
	if len(caCertificates) == 0 {
		return nil
	}

	rootCAs := x509.NewCertPool()

	for _, rootCA := range caCertificates {
		if !utils.IsFileInputValid(rootCA) {
			return fmt.Errorf("invalid root CA certificate %#v", rootCA)
		}
		if rootCA != "" && !filepath.IsAbs(rootCA) {
			rootCA = filepath.Join(configDir, rootCA)
		}
		crt, err := ioutil.ReadFile(rootCA)
		if err != nil {
			return err
		}
		if rootCAs.AppendCertsFromPEM(crt) {
			logger.Debug(logSender, "", "TLS certificate authority %#v successfully loaded", rootCA)
		} else {
			err := fmt.Errorf("unable to load TLS certificate authority %#v", rootCA)
			logger.Debug(logSender, "", "%v", err)
			return err
		}
	}

	m.rootCAs = rootCAs
	return nil
}

// NewCertManager creates a new certificate manager
func NewCertManager(certificateFile, certificateKeyFile, logSender string) (*CertManager, error) {
	manager := &CertManager{
		cert:     nil,
		certPath: certificateFile,
		keyPath:  certificateKeyFile,
	}
	err := manager.LoadCertificate(logSender)
	if err != nil {
		return nil, err
	}
	return manager, nil
}
