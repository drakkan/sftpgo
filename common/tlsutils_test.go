package common

import (
	"crypto/tls"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	httpsCert = `-----BEGIN CERTIFICATE-----
MIICHTCCAaKgAwIBAgIUHnqw7QnB1Bj9oUsNpdb+ZkFPOxMwCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAyMDQwOTUzMDRaFw0zMDAyMDEw
OTUzMDRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAARCjRMqJ85rzMC998X5z761nJ+xL3bkmGVqWvrJ51t5OxV0v25NsOgR82CA
NXUgvhVYs7vNFN+jxtb2aj6Xg+/2G/BNxkaFspIVCzgWkxiz7XE4lgUwX44FCXZM
3+JeUbKjUzBRMB0GA1UdDgQWBBRhLw+/o3+Z02MI/d4tmaMui9W16jAfBgNVHSME
GDAWgBRhLw+/o3+Z02MI/d4tmaMui9W16jAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
SM49BAMCA2kAMGYCMQDqLt2lm8mE+tGgtjDmtFgdOcI72HSbRQ74D5rYTzgST1rY
/8wTi5xl8TiFUyLMUsICMQC5ViVxdXbhuG7gX6yEqSkMKZICHpO8hqFwOD/uaFVI
dV4vKmHUzwK/eIx+8Ay3neE=
-----END CERTIFICATE-----`
	httpsKey = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCfMNsN6miEE3rVyUPwElfiJSWaR5huPCzUenZOfJT04GAcQdWvEju3
UM2lmBLIXpGgBwYFK4EEACKhZANiAARCjRMqJ85rzMC998X5z761nJ+xL3bkmGVq
WvrJ51t5OxV0v25NsOgR82CANXUgvhVYs7vNFN+jxtb2aj6Xg+/2G/BNxkaFspIV
CzgWkxiz7XE4lgUwX44FCXZM3+JeUbI=
-----END EC PRIVATE KEY-----`
)

func TestLoadCertificate(t *testing.T) {
	certPath := filepath.Join(os.TempDir(), "test.crt")
	keyPath := filepath.Join(os.TempDir(), "test.key")
	err := ioutil.WriteFile(certPath, []byte(httpsCert), os.ModePerm)
	assert.NoError(t, err)
	err = ioutil.WriteFile(keyPath, []byte(httpsKey), os.ModePerm)
	assert.NoError(t, err)
	certManager, err := NewCertManager(certPath, keyPath, logSenderTest)
	assert.NoError(t, err)
	certFunc := certManager.GetCertificateFunc()
	if assert.NotNil(t, certFunc) {
		hello := &tls.ClientHelloInfo{
			ServerName:   "localhost",
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
		}
		cert, err := certFunc(hello)
		assert.NoError(t, err)
		assert.Equal(t, certManager.cert, cert)
	}

	err = certManager.LoadRootCAs(nil, "")
	assert.NoError(t, err)

	err = certManager.LoadRootCAs([]string{""}, "")
	assert.Error(t, err)

	err = certManager.LoadRootCAs([]string{"invalid"}, "")
	assert.Error(t, err)

	// laoding the key as root CA must fail
	err = certManager.LoadRootCAs([]string{keyPath}, "")
	assert.Error(t, err)

	err = certManager.LoadRootCAs([]string{certPath}, "")
	assert.NoError(t, err)

	rootCa := certManager.GetRootCAs()
	assert.NotNil(t, rootCa)

	err = os.Remove(certPath)
	assert.NoError(t, err)
	err = os.Remove(keyPath)
	assert.NoError(t, err)
}

func TestLoadInvalidCert(t *testing.T) {
	certManager, err := NewCertManager("test.crt", "test.key", logSenderTest)
	assert.Error(t, err)
	assert.Nil(t, certManager)
}
