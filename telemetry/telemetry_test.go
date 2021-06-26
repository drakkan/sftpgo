package telemetry

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/common"
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

func TestInitialization(t *testing.T) {
	c := Conf{
		BindPort:       10000,
		BindAddress:    "invalid",
		EnableProfiler: false,
	}
	err := c.Initialize(".")
	require.Error(t, err)

	c.AuthUserFile = "missing"
	err = c.Initialize(".")
	require.Error(t, err)

	err = ReloadCertificateMgr()
	require.NoError(t, err)

	c.AuthUserFile = ""
	c.CertificateFile = "crt"
	c.CertificateKeyFile = "key"

	err = c.Initialize(".")
	require.Error(t, err)

	certPath := filepath.Join(os.TempDir(), "test.crt")
	keyPath := filepath.Join(os.TempDir(), "test.key")
	err = os.WriteFile(certPath, []byte(httpsCert), os.ModePerm)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(httpsKey), os.ModePerm)
	require.NoError(t, err)

	c.CertificateFile = certPath
	c.CertificateKeyFile = keyPath

	err = c.Initialize(".")
	require.Error(t, err)

	err = ReloadCertificateMgr()
	require.NoError(t, err)

	err = os.Remove(certPath)
	require.NoError(t, err)
	err = os.Remove(keyPath)
	require.NoError(t, err)
}

func TestShouldBind(t *testing.T) {
	c := Conf{
		BindPort:       10000,
		EnableProfiler: false,
	}
	require.True(t, c.ShouldBind())

	c.BindPort = 0
	require.False(t, c.ShouldBind())

	if runtime.GOOS != "windows" {
		c.BindAddress = "/absolute/path"
		require.True(t, c.ShouldBind())
	}
}

func TestRouter(t *testing.T) {
	authUserFile := filepath.Join(os.TempDir(), "http_users.txt")
	authUserData := []byte("test1:$2y$05$bcHSED7aO1cfLto6ZdDBOOKzlwftslVhtpIkRhAtSa4GuLmk5mola\n")
	err := os.WriteFile(authUserFile, authUserData, os.ModePerm)
	require.NoError(t, err)

	httpAuth, err = common.NewBasicAuthProvider(authUserFile)
	require.NoError(t, err)

	initializeRouter(true)
	testServer := httptest.NewServer(router)
	defer testServer.Close()

	req, err := http.NewRequest(http.MethodGet, "/healthz", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "ok", rr.Body.String())

	req, err = http.NewRequest(http.MethodGet, "/metrics", nil)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)

	req.SetBasicAuth("test1", "password1")
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	req, err = http.NewRequest(http.MethodGet, pprofBasePath+"/pprof/", nil)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)

	req.SetBasicAuth("test1", "password1")
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	httpAuth, err = common.NewBasicAuthProvider("")
	require.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, "/metrics", nil)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	err = os.Remove(authUserFile)
	require.NoError(t, err)
}
