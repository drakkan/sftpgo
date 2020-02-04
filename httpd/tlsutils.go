package httpd

import (
	"crypto/tls"
	"sync"

	"github.com/drakkan/sftpgo/logger"
)

type certManager struct {
	cert     *tls.Certificate
	certPath string
	keyPath  string
	lock     *sync.RWMutex
}

func (m *certManager) loadCertificate() error {
	newCert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		logger.Warn(logSender, "", "unable to load https certificate: %v", err)
		return err
	}
	logger.Debug(logSender, "", "https certificate successfully loaded")
	m.lock.Lock()
	defer m.lock.Unlock()
	m.cert = &newCert
	return nil
}

func (m *certManager) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		m.lock.RLock()
		defer m.lock.RUnlock()
		return m.cert, nil
	}
}

func newCertManager(certificateFile, certificateKeyFile string) (*certManager, error) {
	manager := &certManager{
		cert:     nil,
		certPath: certificateFile,
		keyPath:  certificateKeyFile,
		lock:     new(sync.RWMutex),
	}
	err := manager.loadCertificate()
	if err != nil {
		return nil, err
	}
	return manager, nil
}
