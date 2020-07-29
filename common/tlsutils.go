package common

import (
	"crypto/tls"
	"sync"

	"github.com/drakkan/sftpgo/logger"
)

// CertManager defines a TLS certificate manager
type CertManager struct {
	certPath string
	keyPath  string
	sync.RWMutex
	cert *tls.Certificate
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
