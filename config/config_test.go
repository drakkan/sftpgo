package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/ftpd"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/webdavd"
)

const (
	tempConfigName = "temp"
)

func reset() {
	viper.Reset()
	config.Init()
}

func TestLoadConfigTest(t *testing.T) {
	reset()

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	assert.NotEqual(t, httpd.Conf{}, config.GetHTTPConfig())
	assert.NotEqual(t, dataprovider.Config{}, config.GetProviderConf())
	assert.NotEqual(t, sftpd.Configuration{}, config.GetSFTPDConfig())
	assert.NotEqual(t, httpclient.Config{}, config.GetHTTPConfig())
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, []byte("{invalid json}"), os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, []byte("{\"sftpd\": {\"bind_port\": \"a\"}}"), os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.Error(t, err)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestLoadConfigFileNotFound(t *testing.T) {
	reset()

	viper.SetConfigName("configfile")
	err := config.LoadConfig(os.TempDir(), "")
	assert.NoError(t, err)
}

func TestEmptyBanner(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Banner = " "
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, _ := json.Marshal(c)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	sftpdConf = config.GetSFTPDConfig()
	assert.NotEmpty(t, strings.TrimSpace(sftpdConf.Banner))
	err = os.Remove(configFilePath)
	assert.NoError(t, err)

	ftpdConf := config.GetFTPDConfig()
	ftpdConf.Banner = " "
	c1 := make(map[string]ftpd.Configuration)
	c1["ftpd"] = ftpdConf
	jsonConf, _ = json.Marshal(c1)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	ftpdConf = config.GetFTPDConfig()
	assert.NotEmpty(t, strings.TrimSpace(ftpdConf.Banner))
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidUploadMode(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	commonConf := config.GetCommonConfig()
	commonConf.UploadMode = 10
	c := make(map[string]common.Configuration)
	c["common"] = commonConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	assert.Equal(t, 0, config.GetCommonConfig().UploadMode)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidExternalAuthScope(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.ExternalAuthScope = 100
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	assert.Equal(t, 0, config.GetProviderConf().ExternalAuthScope)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidCredentialsPath(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.CredentialsPath = ""
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	assert.Equal(t, "credentials", config.GetProviderConf().CredentialsPath)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidProxyProtocol(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	commonConf := config.GetCommonConfig()
	commonConf.ProxyProtocol = 10
	c := make(map[string]common.Configuration)
	c["common"] = commonConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	assert.Equal(t, 0, config.GetCommonConfig().ProxyProtocol)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidUsersBaseDir(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.UsersBaseDir = "."
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	assert.Empty(t, config.GetProviderConf().UsersBaseDir)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestSetGetConfig(t *testing.T) {
	reset()

	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.MaxAuthTries = 10
	config.SetSFTPDConfig(sftpdConf)
	assert.Equal(t, sftpdConf.MaxAuthTries, config.GetSFTPDConfig().MaxAuthTries)
	dataProviderConf := config.GetProviderConf()
	dataProviderConf.Host = "test host"
	config.SetProviderConf(dataProviderConf)
	assert.Equal(t, dataProviderConf.Host, config.GetProviderConf().Host)
	httpdConf := config.GetHTTPDConfig()
	httpdConf.Bindings = append(httpdConf.Bindings, httpd.Binding{Address: "0.0.0.0"})
	config.SetHTTPDConfig(httpdConf)
	assert.Equal(t, httpdConf.Bindings[0].Address, config.GetHTTPDConfig().Bindings[0].Address)
	commonConf := config.GetCommonConfig()
	commonConf.IdleTimeout = 10
	config.SetCommonConfig(commonConf)
	assert.Equal(t, commonConf.IdleTimeout, config.GetCommonConfig().IdleTimeout)
	ftpdConf := config.GetFTPDConfig()
	ftpdConf.CertificateFile = "cert"
	ftpdConf.CertificateKeyFile = "key"
	config.SetFTPDConfig(ftpdConf)
	assert.Equal(t, ftpdConf.CertificateFile, config.GetFTPDConfig().CertificateFile)
	assert.Equal(t, ftpdConf.CertificateKeyFile, config.GetFTPDConfig().CertificateKeyFile)
	webDavConf := config.GetWebDAVDConfig()
	webDavConf.CertificateFile = "dav_cert"
	webDavConf.CertificateKeyFile = "dav_key"
	config.SetWebDAVDConfig(webDavConf)
	assert.Equal(t, webDavConf.CertificateFile, config.GetWebDAVDConfig().CertificateFile)
	assert.Equal(t, webDavConf.CertificateKeyFile, config.GetWebDAVDConfig().CertificateKeyFile)
	kmsConf := config.GetKMSConfig()
	kmsConf.Secrets.MasterKeyPath = "apath"
	kmsConf.Secrets.URL = "aurl"
	config.SetKMSConfig(kmsConf)
	assert.Equal(t, kmsConf.Secrets.MasterKeyPath, config.GetKMSConfig().Secrets.MasterKeyPath)
	assert.Equal(t, kmsConf.Secrets.URL, config.GetKMSConfig().Secrets.URL)
	telemetryConf := config.GetTelemetryConfig()
	telemetryConf.BindPort = 10001
	telemetryConf.BindAddress = "0.0.0.0"
	config.SetTelemetryConfig(telemetryConf)
	assert.Equal(t, telemetryConf.BindPort, config.GetTelemetryConfig().BindPort)
	assert.Equal(t, telemetryConf.BindAddress, config.GetTelemetryConfig().BindAddress)
}

func TestServiceToStart(t *testing.T) {
	reset()

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	assert.True(t, config.HasServicesToStart())
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Bindings[0].Port = 0
	config.SetSFTPDConfig(sftpdConf)
	assert.False(t, config.HasServicesToStart())
	ftpdConf := config.GetFTPDConfig()
	ftpdConf.Bindings[0].Port = 2121
	config.SetFTPDConfig(ftpdConf)
	assert.True(t, config.HasServicesToStart())
	ftpdConf.Bindings[0].Port = 0
	config.SetFTPDConfig(ftpdConf)
	webdavdConf := config.GetWebDAVDConfig()
	webdavdConf.Bindings[0].Port = 9000
	config.SetWebDAVDConfig(webdavdConf)
	assert.True(t, config.HasServicesToStart())
	webdavdConf.Bindings[0].Port = 0
	config.SetWebDAVDConfig(webdavdConf)
	assert.False(t, config.HasServicesToStart())
	sftpdConf.Bindings[0].Port = 2022
	config.SetSFTPDConfig(sftpdConf)
	assert.True(t, config.HasServicesToStart())
}

func TestSFTPDBindingsCompatibility(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	sftpdConf := config.GetSFTPDConfig()
	require.Len(t, sftpdConf.Bindings, 1)
	sftpdConf.Bindings = nil
	sftpdConf.BindPort = 9022           //nolint:staticcheck
	sftpdConf.BindAddress = "127.0.0.1" //nolint:staticcheck
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	sftpdConf = config.GetSFTPDConfig()
	// the default binding should be replaced with the deprecated configuration
	require.Len(t, sftpdConf.Bindings, 1)
	require.Equal(t, 9022, sftpdConf.Bindings[0].Port)
	require.Equal(t, "127.0.0.1", sftpdConf.Bindings[0].Address)
	require.True(t, sftpdConf.Bindings[0].ApplyProxyConfig)

	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	sftpdConf = config.GetSFTPDConfig()
	require.Len(t, sftpdConf.Bindings, 1)
	require.Equal(t, 9022, sftpdConf.Bindings[0].Port)
	require.Equal(t, "127.0.0.1", sftpdConf.Bindings[0].Address)
	require.True(t, sftpdConf.Bindings[0].ApplyProxyConfig)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestFTPDBindingsCompatibility(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	ftpdConf := config.GetFTPDConfig()
	require.Len(t, ftpdConf.Bindings, 1)
	ftpdConf.Bindings = nil
	ftpdConf.BindPort = 9022              //nolint:staticcheck
	ftpdConf.BindAddress = "127.1.0.1"    //nolint:staticcheck
	ftpdConf.ForcePassiveIP = "127.1.1.1" //nolint:staticcheck
	ftpdConf.TLSMode = 2                  //nolint:staticcheck
	c := make(map[string]ftpd.Configuration)
	c["ftpd"] = ftpdConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	ftpdConf = config.GetFTPDConfig()
	// the default binding should be replaced with the deprecated configuration
	require.Len(t, ftpdConf.Bindings, 1)
	require.Equal(t, 9022, ftpdConf.Bindings[0].Port)
	require.Equal(t, "127.1.0.1", ftpdConf.Bindings[0].Address)
	require.True(t, ftpdConf.Bindings[0].ApplyProxyConfig)
	require.Equal(t, 2, ftpdConf.Bindings[0].TLSMode)
	require.Equal(t, "127.1.1.1", ftpdConf.Bindings[0].ForcePassiveIP)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestWebDAVDBindingsCompatibility(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	webdavConf := config.GetWebDAVDConfig()
	require.Len(t, webdavConf.Bindings, 1)
	webdavConf.Bindings = nil
	webdavConf.BindPort = 9080           //nolint:staticcheck
	webdavConf.BindAddress = "127.0.0.1" //nolint:staticcheck
	c := make(map[string]webdavd.Configuration)
	c["webdavd"] = webdavConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	webdavConf = config.GetWebDAVDConfig()
	// the default binding should be replaced with the deprecated configuration
	require.Len(t, webdavConf.Bindings, 1)
	require.Equal(t, 9080, webdavConf.Bindings[0].Port)
	require.Equal(t, "127.0.0.1", webdavConf.Bindings[0].Address)
	require.False(t, webdavConf.Bindings[0].EnableHTTPS)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestHTTPDBindingsCompatibility(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	httpdConf := config.GetHTTPDConfig()
	require.Len(t, httpdConf.Bindings, 1)
	httpdConf.Bindings = nil
	httpdConf.BindPort = 9080           //nolint:staticcheck
	httpdConf.BindAddress = "127.1.1.1" //nolint:staticcheck
	c := make(map[string]httpd.Conf)
	c["httpd"] = httpdConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	httpdConf = config.GetHTTPDConfig()
	// the default binding should be replaced with the deprecated configuration
	require.Len(t, httpdConf.Bindings, 1)
	require.Equal(t, 9080, httpdConf.Bindings[0].Port)
	require.Equal(t, "127.1.1.1", httpdConf.Bindings[0].Address)
	require.False(t, httpdConf.Bindings[0].EnableHTTPS)
	require.True(t, httpdConf.Bindings[0].EnableWebAdmin)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestSFTPDBindingsFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_SFTPD__BINDINGS__0__ADDRESS", "127.0.0.1")
	os.Setenv("SFTPGO_SFTPD__BINDINGS__0__PORT", "2200")
	os.Setenv("SFTPGO_SFTPD__BINDINGS__0__APPLY_PROXY_CONFIG", "false")
	os.Setenv("SFTPGO_SFTPD__BINDINGS__3__ADDRESS", "127.0.1.1")
	os.Setenv("SFTPGO_SFTPD__BINDINGS__3__PORT", "2203")
	os.Setenv("SFTPGO_SFTPD__BINDINGS__3__APPLY_PROXY_CONFIG", "1")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__0__ADDRESS")
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__0__PORT")
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__0__APPLY_PROXY_CONFIG")
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__3__ADDRESS")
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__3__PORT")
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__3__APPLY_PROXY_CONFIG")
	})

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	bindings := config.GetSFTPDConfig().Bindings
	require.Len(t, bindings, 2)
	require.Equal(t, 2200, bindings[0].Port)
	require.Equal(t, "127.0.0.1", bindings[0].Address)
	require.False(t, bindings[0].ApplyProxyConfig)
	require.Equal(t, 2203, bindings[1].Port)
	require.Equal(t, "127.0.1.1", bindings[1].Address)
	require.True(t, bindings[1].ApplyProxyConfig)
}

func TestFTPDBindingsFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_FTPD__BINDINGS__0__ADDRESS", "127.0.0.1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__PORT", "2200")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__APPLY_PROXY_CONFIG", "f")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__TLS_MODE", "2")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__FORCE_PASSIVE_IP", "127.0.1.2")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__TLS_CIPHER_SUITES", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__ADDRESS", "127.0.1.1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__PORT", "2203")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__APPLY_PROXY_CONFIG", "t")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__TLS_MODE", "1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__FORCE_PASSIVE_IP", "127.0.1.1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__CLIENT_AUTH_TYPE", "2")

	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__ADDRESS")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__PORT")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__APPLY_PROXY_CONFIG")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__TLS_MODE")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__FORCE_PASSIVE_IP")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__TLS_CIPHER_SUITES")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__ADDRESS")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__PORT")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__APPLY_PROXY_CONFIG")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__TLS_MODE")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__FORCE_PASSIVE_IP")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__CLIENT_AUTH_TYPE")
	})

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	bindings := config.GetFTPDConfig().Bindings
	require.Len(t, bindings, 2)
	require.Equal(t, 2200, bindings[0].Port)
	require.Equal(t, "127.0.0.1", bindings[0].Address)
	require.False(t, bindings[0].ApplyProxyConfig)
	require.Equal(t, 2, bindings[0].TLSMode)
	require.Equal(t, "127.0.1.2", bindings[0].ForcePassiveIP)
	require.Equal(t, 0, bindings[0].ClientAuthType)
	require.Len(t, bindings[0].TLSCipherSuites, 2)
	require.Equal(t, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", bindings[0].TLSCipherSuites[0])
	require.Equal(t, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", bindings[0].TLSCipherSuites[1])
	require.Equal(t, 2203, bindings[1].Port)
	require.Equal(t, "127.0.1.1", bindings[1].Address)
	require.True(t, bindings[1].ApplyProxyConfig)
	require.Equal(t, 1, bindings[1].TLSMode)
	require.Equal(t, "127.0.1.1", bindings[1].ForcePassiveIP)
	require.Equal(t, 2, bindings[1].ClientAuthType)
	require.Nil(t, bindings[1].TLSCipherSuites)
}

func TestWebDAVBindingsFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__1__ADDRESS", "127.0.0.1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__1__PORT", "8000")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__1__ENABLE_HTTPS", "0")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__1__TLS_CIPHER_SUITES", "TLS_RSA_WITH_AES_128_CBC_SHA ")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__ADDRESS", "127.0.1.1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__PORT", "9000")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__ENABLE_HTTPS", "1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__CLIENT_AUTH_TYPE", "1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__PREFIX", "/dav2")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__1__ADDRESS")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__1__PORT")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__1__ENABLE_HTTPS")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__1__TLS_CIPHER_SUITES")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__2__ADDRESS")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__2__PORT")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__2__ENABLE_HTTPS")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__2__CLIENT_AUTH_TYPE")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__2__PREFIX")
	})

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	bindings := config.GetWebDAVDConfig().Bindings
	require.Len(t, bindings, 3)
	require.Equal(t, 0, bindings[0].Port)
	require.Empty(t, bindings[0].Address)
	require.False(t, bindings[0].EnableHTTPS)
	require.Len(t, bindings[0].TLSCipherSuites, 0)
	require.Empty(t, bindings[0].Prefix)
	require.Equal(t, 8000, bindings[1].Port)
	require.Equal(t, "127.0.0.1", bindings[1].Address)
	require.False(t, bindings[1].EnableHTTPS)
	require.Equal(t, 0, bindings[1].ClientAuthType)
	require.Len(t, bindings[1].TLSCipherSuites, 1)
	require.Equal(t, "TLS_RSA_WITH_AES_128_CBC_SHA", bindings[1].TLSCipherSuites[0])
	require.Empty(t, bindings[1].Prefix)
	require.Equal(t, 9000, bindings[2].Port)
	require.Equal(t, "127.0.1.1", bindings[2].Address)
	require.True(t, bindings[2].EnableHTTPS)
	require.Equal(t, 1, bindings[2].ClientAuthType)
	require.Nil(t, bindings[2].TLSCipherSuites)
	require.Equal(t, "/dav2", bindings[2].Prefix)
}

func TestHTTPDBindingsFromEnv(t *testing.T) {
	reset()

	sockPath := filepath.Clean(os.TempDir())

	os.Setenv("SFTPGO_HTTPD__BINDINGS__0__ADDRESS", sockPath)
	os.Setenv("SFTPGO_HTTPD__BINDINGS__0__PORT", "0")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__0__TLS_CIPHER_SUITES", " TLS_AES_128_GCM_SHA256")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__1__ADDRESS", "127.0.0.1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__1__PORT", "8000")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__1__ENABLE_HTTPS", "0")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__1__ENABLE_WEB_ADMIN", "1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__ADDRESS", "127.0.1.1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__PORT", "9000")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__ENABLE_WEB_ADMIN", "0")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__ENABLE_HTTPS", "1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__CLIENT_AUTH_TYPE", "1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__TLS_CIPHER_SUITES", " TLS_AES_256_GCM_SHA384 , TLS_CHACHA20_POLY1305_SHA256")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__0__ADDRESS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__0__PORT")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__0__TLS_CIPHER_SUITES")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__1__ADDRESS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__1__PORT")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__1__ENABLE_HTTPS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__1__ENABLE_WEB_ADMIN")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__ADDRESS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__PORT")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__ENABLE_HTTPS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__ENABLE_WEB_ADMIN")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__CLIENT_AUTH_TYPE")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__TLS_CIPHER_SUITES")
	})

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	bindings := config.GetHTTPDConfig().Bindings
	require.Len(t, bindings, 3)
	require.Equal(t, 0, bindings[0].Port)
	require.Equal(t, sockPath, bindings[0].Address)
	require.False(t, bindings[0].EnableHTTPS)
	require.True(t, bindings[0].EnableWebAdmin)
	require.Len(t, bindings[0].TLSCipherSuites, 1)
	require.Equal(t, "TLS_AES_128_GCM_SHA256", bindings[0].TLSCipherSuites[0])
	require.Equal(t, 8000, bindings[1].Port)
	require.Equal(t, "127.0.0.1", bindings[1].Address)
	require.False(t, bindings[1].EnableHTTPS)
	require.True(t, bindings[1].EnableWebAdmin)
	require.Nil(t, bindings[1].TLSCipherSuites)

	require.Equal(t, 9000, bindings[2].Port)
	require.Equal(t, "127.0.1.1", bindings[2].Address)
	require.True(t, bindings[2].EnableHTTPS)
	require.False(t, bindings[2].EnableWebAdmin)
	require.Equal(t, 1, bindings[2].ClientAuthType)
	require.Len(t, bindings[2].TLSCipherSuites, 2)
	require.Equal(t, "TLS_AES_256_GCM_SHA384", bindings[2].TLSCipherSuites[0])
	require.Equal(t, "TLS_CHACHA20_POLY1305_SHA256", bindings[2].TLSCipherSuites[1])
}

func TestHTTPClientCertificatesFromEnv(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	httpConf := config.GetHTTPConfig()
	httpConf.Certificates = append(httpConf.Certificates, httpclient.TLSKeyPair{
		Cert: "cert",
		Key:  "key",
	})
	c := make(map[string]httpclient.Config)
	c["http"] = httpConf
	jsonConf, err := json.Marshal(c)
	require.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	require.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	require.NoError(t, err)
	require.Len(t, config.GetHTTPConfig().Certificates, 1)
	require.Equal(t, "cert", config.GetHTTPConfig().Certificates[0].Cert)
	require.Equal(t, "key", config.GetHTTPConfig().Certificates[0].Key)

	os.Setenv("SFTPGO_HTTP__CERTIFICATES__0__CERT", "cert0")
	os.Setenv("SFTPGO_HTTP__CERTIFICATES__0__KEY", "key0")
	os.Setenv("SFTPGO_HTTP__CERTIFICATES__8__CERT", "cert8")
	os.Setenv("SFTPGO_HTTP__CERTIFICATES__9__CERT", "cert9")
	os.Setenv("SFTPGO_HTTP__CERTIFICATES__9__KEY", "key9")

	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_HTTP__CERTIFICATES__0__CERT")
		os.Unsetenv("SFTPGO_HTTP__CERTIFICATES__0__KEY")
		os.Unsetenv("SFTPGO_HTTP__CERTIFICATES__8__CERT")
		os.Unsetenv("SFTPGO_HTTP__CERTIFICATES__9__CERT")
		os.Unsetenv("SFTPGO_HTTP__CERTIFICATES__9__KEY")
	})

	err = config.LoadConfig(configDir, confName)
	require.NoError(t, err)
	require.Len(t, config.GetHTTPConfig().Certificates, 2)
	require.Equal(t, "cert0", config.GetHTTPConfig().Certificates[0].Cert)
	require.Equal(t, "key0", config.GetHTTPConfig().Certificates[0].Key)
	require.Equal(t, "cert9", config.GetHTTPConfig().Certificates[1].Cert)
	require.Equal(t, "key9", config.GetHTTPConfig().Certificates[1].Key)

	err = os.Remove(configFilePath)
	assert.NoError(t, err)

	config.Init()

	err = config.LoadConfig(configDir, "")
	require.NoError(t, err)
	require.Len(t, config.GetHTTPConfig().Certificates, 2)
	require.Equal(t, "cert0", config.GetHTTPConfig().Certificates[0].Cert)
	require.Equal(t, "key0", config.GetHTTPConfig().Certificates[0].Key)
	require.Equal(t, "cert9", config.GetHTTPConfig().Certificates[1].Cert)
	require.Equal(t, "key9", config.GetHTTPConfig().Certificates[1].Key)
}

func TestConfigFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_SFTPD__BINDINGS__0__ADDRESS", "127.0.0.1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__0__PORT", "12000")
	os.Setenv("SFTPGO_DATA_PROVIDER__PASSWORD_HASHING__ARGON2_OPTIONS__ITERATIONS", "41")
	os.Setenv("SFTPGO_DATA_PROVIDER__POOL_SIZE", "10")
	os.Setenv("SFTPGO_DATA_PROVIDER__ACTIONS__EXECUTE_ON", "add")
	os.Setenv("SFTPGO_KMS__SECRETS__URL", "local")
	os.Setenv("SFTPGO_KMS__SECRETS__MASTER_KEY_PATH", "path")
	os.Setenv("SFTPGO_TELEMETRY__TLS_CIPHER_SUITES", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__0__ADDRESS")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__0__PORT")
		os.Unsetenv("SFTPGO_DATA_PROVIDER__PASSWORD_HASHING__ARGON2_OPTIONS__ITERATIONS")
		os.Unsetenv("SFTPGO_DATA_PROVIDER__POOL_SIZE")
		os.Unsetenv("SFTPGO_DATA_PROVIDER__ACTIONS__EXECUTE_ON")
		os.Unsetenv("SFTPGO_KMS__SECRETS__URL")
		os.Unsetenv("SFTPGO_KMS__SECRETS__MASTER_KEY_PATH")
		os.Unsetenv("SFTPGO_TELEMETRY__TLS_CIPHER_SUITES")
	})
	err := config.LoadConfig(".", "invalid config")
	assert.NoError(t, err)
	sftpdConfig := config.GetSFTPDConfig()
	assert.Equal(t, "127.0.0.1", sftpdConfig.Bindings[0].Address)
	assert.Equal(t, 12000, config.GetWebDAVDConfig().Bindings[0].Port)
	dataProviderConf := config.GetProviderConf()
	assert.Equal(t, uint32(41), dataProviderConf.PasswordHashing.Argon2Options.Iterations)
	assert.Equal(t, 10, dataProviderConf.PoolSize)
	assert.Len(t, dataProviderConf.Actions.ExecuteOn, 1)
	assert.Contains(t, dataProviderConf.Actions.ExecuteOn, "add")
	kmsConfig := config.GetKMSConfig()
	assert.Equal(t, "local", kmsConfig.Secrets.URL)
	assert.Equal(t, "path", kmsConfig.Secrets.MasterKeyPath)
	telemetryConfig := config.GetTelemetryConfig()
	assert.Len(t, telemetryConfig.TLSCipherSuites, 2)
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", telemetryConfig.TLSCipherSuites[0])
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", telemetryConfig.TLSCipherSuites[1])
}
