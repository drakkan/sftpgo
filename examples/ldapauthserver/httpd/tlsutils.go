package httpd

import (
	"crypto/tls"
	"sync"

	"github.com/drakkan/sftpgo/ldapauthserver/logger"
)

type certManager struct {
	certPath string
	keyPath  string
	sync.RWMutex
	cert *tls.Certificate
}

func (m *certManager) loadCertificate() error {
	newCert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		logger.Warn(logSender, "", "unable to load https certificate: %v", err)
		return err
	}
	logger.Debug(logSender, "", "https certificate successfully loaded")
	m.Lock()
	defer m.Unlock()
	m.cert = &newCert
	return nil
}

func (m *certManager) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		m.RLock()
		defer m.RUnlock()
		return m.cert, nil
	}
}

func newCertManager(certificateFile, certificateKeyFile string) (*certManager, error) {
	manager := &certManager{
		cert:     nil,
		certPath: certificateFile,
		keyPath:  certificateKeyFile,
	}
	err := manager.loadCertificate()
	if err != nil {
		return nil, err
	}
	return manager, nil
}
