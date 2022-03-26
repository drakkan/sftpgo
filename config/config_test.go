package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sftpgo/sdk/kms"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/ftpd"
	"github.com/drakkan/sftpgo/v2/httpclient"
	"github.com/drakkan/sftpgo/v2/httpd"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/plugin"
	"github.com/drakkan/sftpgo/v2/sftpd"
	"github.com/drakkan/sftpgo/v2/smtp"
	"github.com/drakkan/sftpgo/v2/util"
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
	assert.NotEqual(t, smtp.Config{}, config.GetSMTPConfig())
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, []byte("{invalid json}"), os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, []byte(`{"sftpd": {"max_auth_tries": "a"}}`), os.ModePerm)
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
	mfaConf := config.GetMFAConfig()
	assert.Len(t, mfaConf.TOTP, 1)
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

func TestEnabledSSHCommands(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)

	reset()

	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.EnabledSSHCommands = []string{"scp"}
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	sftpdConf = config.GetSFTPDConfig()
	if assert.Len(t, sftpdConf.EnabledSSHCommands, 1) {
		assert.Equal(t, "scp", sftpdConf.EnabledSSHCommands[0])
	}
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

func TestInvalidInstallationHint(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	httpdConfig := config.GetHTTPDConfig()
	httpdConfig.Setup = httpd.SetupConfig{
		InstallationCode:     "abc",
		InstallationCodeHint: " ",
	}
	c := make(map[string]httpd.Conf)
	c["httpd"] = httpdConfig
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	httpdConfig = config.GetHTTPDConfig()
	assert.Equal(t, "abc", httpdConfig.Setup.InstallationCode)
	assert.Equal(t, "Installation code", httpdConfig.Setup.InstallationCodeHint)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestDefenderProviderDriver(t *testing.T) {
	if config.GetProviderConf().Driver != dataprovider.SQLiteDataProviderName {
		t.Skip("this test is not supported with the current database provider")
	}
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	providerConf := config.GetProviderConf()
	providerConf.Driver = dataprovider.BoltDataProviderName
	commonConfig := config.GetCommonConfig()
	commonConfig.DefenderConfig.Enabled = true
	commonConfig.DefenderConfig.Driver = common.DefenderDriverProvider
	c := make(map[string]interface{})
	c["common"] = commonConfig
	c["data_provider"] = providerConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	assert.Equal(t, dataprovider.BoltDataProviderName, config.GetProviderConf().Driver)
	assert.Equal(t, common.DefenderDriverMemory, config.GetCommonConfig().DefenderConfig.Driver)
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
	pluginConf := []plugin.Config{
		{
			Type: "eventsearcher",
		},
	}
	config.SetPluginsConfig(pluginConf)
	if assert.Len(t, config.GetPluginsConfig(), 1) {
		assert.Equal(t, pluginConf[0].Type, config.GetPluginsConfig()[0].Type)
	}
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

func TestSSHCommandsFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_SFTPD__ENABLED_SSH_COMMANDS", "cd,scp")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_SFTPD__ENABLED_SSH_COMMANDS")
	})

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)

	sftpdConf := config.GetSFTPDConfig()
	if assert.Len(t, sftpdConf.EnabledSSHCommands, 2) {
		assert.Equal(t, "cd", sftpdConf.EnabledSSHCommands[0])
		assert.Equal(t, "scp", sftpdConf.EnabledSSHCommands[1])
	}
}

func TestSMTPFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_SMTP__HOST", "smtp.example.com")
	os.Setenv("SFTPGO_SMTP__PORT", "587")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_SMTP__HOST")
		os.Unsetenv("SFTPGO_SMTP__PORT")
	})

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	smtpConfig := config.GetSMTPConfig()
	assert.Equal(t, "smtp.example.com", smtpConfig.Host)
	assert.Equal(t, 587, smtpConfig.Port)
}

func TestMFAFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_MFA__TOTP__0__NAME", "main")
	os.Setenv("SFTPGO_MFA__TOTP__1__NAME", "additional_name")
	os.Setenv("SFTPGO_MFA__TOTP__1__ISSUER", "additional_issuer")
	os.Setenv("SFTPGO_MFA__TOTP__1__ALGO", "sha256")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_MFA__TOTP__0__NAME")
		os.Unsetenv("SFTPGO_MFA__TOTP__1__NAME")
		os.Unsetenv("SFTPGO_MFA__TOTP__1__ISSUER")
		os.Unsetenv("SFTPGO_MFA__TOTP__1__ALGO")
	})

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	mfaConf := config.GetMFAConfig()
	require.Len(t, mfaConf.TOTP, 2)
	require.Equal(t, "main", mfaConf.TOTP[0].Name)
	require.Equal(t, "SFTPGo", mfaConf.TOTP[0].Issuer)
	require.Equal(t, "sha1", mfaConf.TOTP[0].Algo)
	require.Equal(t, "additional_name", mfaConf.TOTP[1].Name)
	require.Equal(t, "additional_issuer", mfaConf.TOTP[1].Issuer)
	require.Equal(t, "sha256", mfaConf.TOTP[1].Algo)
}

func TestDisabledMFAConfig(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)

	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	mfaConf := config.GetMFAConfig()
	assert.Len(t, mfaConf.TOTP, 1)

	reset()

	c := make(map[string]mfa.Config)
	c["mfa"] = mfa.Config{}
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	mfaConf = config.GetMFAConfig()
	assert.Len(t, mfaConf.TOTP, 0)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestPluginsFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_PLUGINS__0__TYPE", "notifier")
	os.Setenv("SFTPGO_PLUGINS__0__NOTIFIER_OPTIONS__FS_EVENTS", "upload,download")
	os.Setenv("SFTPGO_PLUGINS__0__NOTIFIER_OPTIONS__PROVIDER_EVENTS", "add,update")
	os.Setenv("SFTPGO_PLUGINS__0__NOTIFIER_OPTIONS__PROVIDER_OBJECTS", "user,admin")
	os.Setenv("SFTPGO_PLUGINS__0__NOTIFIER_OPTIONS__RETRY_MAX_TIME", "2")
	os.Setenv("SFTPGO_PLUGINS__0__NOTIFIER_OPTIONS__RETRY_QUEUE_MAX_SIZE", "1000")
	os.Setenv("SFTPGO_PLUGINS__0__CMD", "plugin_start_cmd")
	os.Setenv("SFTPGO_PLUGINS__0__ARGS", "arg1,arg2")
	os.Setenv("SFTPGO_PLUGINS__0__SHA256SUM", "0a71ded61fccd59c4f3695b51c1b3d180da8d2d77ea09ccee20dac242675c193")
	os.Setenv("SFTPGO_PLUGINS__0__AUTO_MTLS", "1")
	os.Setenv("SFTPGO_PLUGINS__0__KMS_OPTIONS__SCHEME", kms.SchemeAWS)
	os.Setenv("SFTPGO_PLUGINS__0__KMS_OPTIONS__ENCRYPTED_STATUS", kms.SecretStatusAWS)
	os.Setenv("SFTPGO_PLUGINS__0__AUTH_OPTIONS__SCOPE", "14")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_PLUGINS__0__TYPE")
		os.Unsetenv("SFTPGO_PLUGINS__0__NOTIFIER_OPTIONS__FS_EVENTS")
		os.Unsetenv("SFTPGO_PLUGINS__0__NOTIFIER_OPTIONS__PROVIDER_EVENTS")
		os.Unsetenv("SFTPGO_PLUGINS__0__NOTIFIER_OPTIONS__PROVIDER_OBJECTS")
		os.Unsetenv("SFTPGO_PLUGINS__0__NOTIFIER_OPTIONS__RETRY_MAX_TIME")
		os.Unsetenv("SFTPGO_PLUGINS__0__NOTIFIER_OPTIONS__RETRY_QUEUE_MAX_SIZE")
		os.Unsetenv("SFTPGO_PLUGINS__0__CMD")
		os.Unsetenv("SFTPGO_PLUGINS__0__ARGS")
		os.Unsetenv("SFTPGO_PLUGINS__0__SHA256SUM")
		os.Unsetenv("SFTPGO_PLUGINS__0__AUTO_MTLS")
		os.Unsetenv("SFTPGO_PLUGINS__0__KMS_OPTIONS__SCHEME")
		os.Unsetenv("SFTPGO_PLUGINS__0__KMS_OPTIONS__ENCRYPTED_STATUS")
		os.Unsetenv("SFTPGO_PLUGINS__0__AUTH_OPTIONS__SCOPE")
	})

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	pluginsConf := config.GetPluginsConfig()
	require.Len(t, pluginsConf, 1)
	pluginConf := pluginsConf[0]
	require.Equal(t, "notifier", pluginConf.Type)
	require.Len(t, pluginConf.NotifierOptions.FsEvents, 2)
	require.True(t, util.IsStringInSlice("upload", pluginConf.NotifierOptions.FsEvents))
	require.True(t, util.IsStringInSlice("download", pluginConf.NotifierOptions.FsEvents))
	require.Len(t, pluginConf.NotifierOptions.ProviderEvents, 2)
	require.Equal(t, "add", pluginConf.NotifierOptions.ProviderEvents[0])
	require.Equal(t, "update", pluginConf.NotifierOptions.ProviderEvents[1])
	require.Len(t, pluginConf.NotifierOptions.ProviderObjects, 2)
	require.Equal(t, "user", pluginConf.NotifierOptions.ProviderObjects[0])
	require.Equal(t, "admin", pluginConf.NotifierOptions.ProviderObjects[1])
	require.Equal(t, 2, pluginConf.NotifierOptions.RetryMaxTime)
	require.Equal(t, 1000, pluginConf.NotifierOptions.RetryQueueMaxSize)
	require.Equal(t, "plugin_start_cmd", pluginConf.Cmd)
	require.Len(t, pluginConf.Args, 2)
	require.Equal(t, "arg1", pluginConf.Args[0])
	require.Equal(t, "arg2", pluginConf.Args[1])
	require.Equal(t, "0a71ded61fccd59c4f3695b51c1b3d180da8d2d77ea09ccee20dac242675c193", pluginConf.SHA256Sum)
	require.True(t, pluginConf.AutoMTLS)
	require.Equal(t, kms.SchemeAWS, pluginConf.KMSOptions.Scheme)
	require.Equal(t, kms.SecretStatusAWS, pluginConf.KMSOptions.EncryptedStatus)
	require.Equal(t, 14, pluginConf.AuthOptions.Scope)

	configAsJSON, err := json.Marshal(pluginsConf)
	require.NoError(t, err)
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err = os.WriteFile(configFilePath, configAsJSON, os.ModePerm)
	assert.NoError(t, err)

	os.Setenv("SFTPGO_PLUGINS__0__CMD", "plugin_start_cmd1")
	os.Setenv("SFTPGO_PLUGINS__0__ARGS", "")
	os.Setenv("SFTPGO_PLUGINS__0__AUTO_MTLS", "0")
	os.Setenv("SFTPGO_PLUGINS__0__KMS_OPTIONS__SCHEME", kms.SchemeVaultTransit)
	os.Setenv("SFTPGO_PLUGINS__0__KMS_OPTIONS__ENCRYPTED_STATUS", kms.SecretStatusVaultTransit)
	err = config.LoadConfig(configDir, confName)
	assert.NoError(t, err)
	pluginsConf = config.GetPluginsConfig()
	require.Len(t, pluginsConf, 1)
	pluginConf = pluginsConf[0]
	require.Equal(t, "notifier", pluginConf.Type)
	require.Len(t, pluginConf.NotifierOptions.FsEvents, 2)
	require.True(t, util.IsStringInSlice("upload", pluginConf.NotifierOptions.FsEvents))
	require.True(t, util.IsStringInSlice("download", pluginConf.NotifierOptions.FsEvents))
	require.Len(t, pluginConf.NotifierOptions.ProviderEvents, 2)
	require.Equal(t, "add", pluginConf.NotifierOptions.ProviderEvents[0])
	require.Equal(t, "update", pluginConf.NotifierOptions.ProviderEvents[1])
	require.Len(t, pluginConf.NotifierOptions.ProviderObjects, 2)
	require.Equal(t, "user", pluginConf.NotifierOptions.ProviderObjects[0])
	require.Equal(t, "admin", pluginConf.NotifierOptions.ProviderObjects[1])
	require.Equal(t, 2, pluginConf.NotifierOptions.RetryMaxTime)
	require.Equal(t, 1000, pluginConf.NotifierOptions.RetryQueueMaxSize)
	require.Equal(t, "plugin_start_cmd1", pluginConf.Cmd)
	require.Len(t, pluginConf.Args, 0)
	require.Equal(t, "0a71ded61fccd59c4f3695b51c1b3d180da8d2d77ea09ccee20dac242675c193", pluginConf.SHA256Sum)
	require.False(t, pluginConf.AutoMTLS)
	require.Equal(t, kms.SchemeVaultTransit, pluginConf.KMSOptions.Scheme)
	require.Equal(t, kms.SecretStatusVaultTransit, pluginConf.KMSOptions.EncryptedStatus)
	require.Equal(t, 14, pluginConf.AuthOptions.Scope)

	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestRateLimitersFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__0__AVERAGE", "100")
	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__0__PERIOD", "2000")
	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__0__BURST", "10")
	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__0__TYPE", "2")
	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__0__PROTOCOLS", "SSH, FTP")
	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__0__GENERATE_DEFENDER_EVENTS", "1")
	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__0__ENTRIES_SOFT_LIMIT", "50")
	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__0__ENTRIES_HARD_LIMIT", "100")
	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__0__ALLOW_LIST", ", 172.16.2.4, ")
	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__8__AVERAGE", "50")
	os.Setenv("SFTPGO_COMMON__RATE_LIMITERS__8__ALLOW_LIST", "192.168.1.1, 192.168.2.0/24")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__0__AVERAGE")
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__0__PERIOD")
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__0__BURST")
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__0__TYPE")
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__0__PROTOCOLS")
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__0__GENERATE_DEFENDER_EVENTS")
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__0__ENTRIES_SOFT_LIMIT")
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__0__ENTRIES_HARD_LIMIT")
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__0__ALLOW_LIST")
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__8__AVERAGE")
		os.Unsetenv("SFTPGO_COMMON__RATE_LIMITERS__8__ALLOW_LIST")
	})

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	limiters := config.GetCommonConfig().RateLimitersConfig
	require.Len(t, limiters, 2)
	require.Equal(t, int64(100), limiters[0].Average)
	require.Equal(t, int64(2000), limiters[0].Period)
	require.Equal(t, 10, limiters[0].Burst)
	require.Equal(t, 2, limiters[0].Type)
	protocols := limiters[0].Protocols
	require.Len(t, protocols, 2)
	require.True(t, util.IsStringInSlice(common.ProtocolFTP, protocols))
	require.True(t, util.IsStringInSlice(common.ProtocolSSH, protocols))
	require.True(t, limiters[0].GenerateDefenderEvents)
	require.Equal(t, 50, limiters[0].EntriesSoftLimit)
	require.Equal(t, 100, limiters[0].EntriesHardLimit)
	require.Len(t, limiters[0].AllowList, 1)
	require.Equal(t, "172.16.2.4", limiters[0].AllowList[0])
	require.Equal(t, int64(50), limiters[1].Average)
	require.Len(t, limiters[1].AllowList, 2)
	require.Equal(t, "192.168.1.1", limiters[1].AllowList[0])
	require.Equal(t, "192.168.2.0/24", limiters[1].AllowList[1])
	// we check the default values here
	require.Equal(t, int64(1000), limiters[1].Period)
	require.Equal(t, 1, limiters[1].Burst)
	require.Equal(t, 2, limiters[1].Type)
	protocols = limiters[1].Protocols
	require.Len(t, protocols, 4)
	require.True(t, util.IsStringInSlice(common.ProtocolFTP, protocols))
	require.True(t, util.IsStringInSlice(common.ProtocolSSH, protocols))
	require.True(t, util.IsStringInSlice(common.ProtocolWebDAV, protocols))
	require.True(t, util.IsStringInSlice(common.ProtocolHTTP, protocols))
	require.False(t, limiters[1].GenerateDefenderEvents)
	require.Equal(t, 100, limiters[1].EntriesSoftLimit)
	require.Equal(t, 150, limiters[1].EntriesHardLimit)
}

func TestSFTPDBindingsFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_SFTPD__BINDINGS__0__ADDRESS", "127.0.0.1")
	os.Setenv("SFTPGO_SFTPD__BINDINGS__0__PORT", "2200")
	os.Setenv("SFTPGO_SFTPD__BINDINGS__0__APPLY_PROXY_CONFIG", "false")
	os.Setenv("SFTPGO_SFTPD__BINDINGS__3__ADDRESS", "127.0.1.1")
	os.Setenv("SFTPGO_SFTPD__BINDINGS__3__PORT", "2203")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__0__ADDRESS")
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__0__PORT")
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__0__APPLY_PROXY_CONFIG")
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__3__ADDRESS")
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__3__PORT")
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
	require.True(t, bindings[1].ApplyProxyConfig) // default value
}

func TestFTPDBindingsFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_FTPD__BINDINGS__0__ADDRESS", "127.0.0.1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__PORT", "2200")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__APPLY_PROXY_CONFIG", "f")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__TLS_MODE", "2")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__FORCE_PASSIVE_IP", "127.0.1.2")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__PASSIVE_IP_OVERRIDES__0__IP", "172.16.1.1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__TLS_CIPHER_SUITES", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	os.Setenv("SFTPGO_FTPD__BINDINGS__0__PASSIVE_CONNECTIONS_SECURITY", "1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__ADDRESS", "127.0.1.1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__PORT", "2203")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__TLS_MODE", "1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__MIN_TLS_VERSION", "13")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__FORCE_PASSIVE_IP", "127.0.1.1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__PASSIVE_IP_OVERRIDES__3__IP", "192.168.1.1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__PASSIVE_IP_OVERRIDES__3__NETWORKS", "192.168.1.0/24, 192.168.3.0/25")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__CLIENT_AUTH_TYPE", "2")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__DEBUG", "1")
	os.Setenv("SFTPGO_FTPD__BINDINGS__9__ACTIVE_CONNECTIONS_SECURITY", "1")

	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__ADDRESS")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__PORT")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__APPLY_PROXY_CONFIG")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__TLS_MODE")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__FORCE_PASSIVE_IP")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__PASSIVE_IP_OVERRIDES__0__IP")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__TLS_CIPHER_SUITES")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__0__ACTIVE_CONNECTIONS_SECURITY")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__ADDRESS")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__PORT")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__TLS_MODE")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__MIN_TLS_VERSION")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__FORCE_PASSIVE_IP")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__PASSIVE_IP_OVERRIDES__3__IP")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__PASSIVE_IP_OVERRIDES__3__NETWORKS")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__CLIENT_AUTH_TYPE")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__DEBUG")
		os.Unsetenv("SFTPGO_FTPD__BINDINGS__9__ACTIVE_CONNECTIONS_SECURITY")
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
	require.Equal(t, 12, bindings[0].MinTLSVersion)
	require.Equal(t, "127.0.1.2", bindings[0].ForcePassiveIP)
	require.Len(t, bindings[0].PassiveIPOverrides, 0)
	require.Equal(t, 0, bindings[0].ClientAuthType)
	require.Len(t, bindings[0].TLSCipherSuites, 2)
	require.Equal(t, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", bindings[0].TLSCipherSuites[0])
	require.Equal(t, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", bindings[0].TLSCipherSuites[1])
	require.False(t, bindings[0].Debug)
	require.Equal(t, 1, bindings[0].PassiveConnectionsSecurity)
	require.Equal(t, 0, bindings[0].ActiveConnectionsSecurity)
	require.Equal(t, 2203, bindings[1].Port)
	require.Equal(t, "127.0.1.1", bindings[1].Address)
	require.True(t, bindings[1].ApplyProxyConfig) // default value
	require.Equal(t, 1, bindings[1].TLSMode)
	require.Equal(t, 13, bindings[1].MinTLSVersion)
	require.Equal(t, "127.0.1.1", bindings[1].ForcePassiveIP)
	require.Len(t, bindings[1].PassiveIPOverrides, 1)
	require.Equal(t, "192.168.1.1", bindings[1].PassiveIPOverrides[0].IP)
	require.Len(t, bindings[1].PassiveIPOverrides[0].Networks, 2)
	require.Equal(t, "192.168.1.0/24", bindings[1].PassiveIPOverrides[0].Networks[0])
	require.Equal(t, "192.168.3.0/25", bindings[1].PassiveIPOverrides[0].Networks[1])
	require.Equal(t, 2, bindings[1].ClientAuthType)
	require.Nil(t, bindings[1].TLSCipherSuites)
	require.Equal(t, 0, bindings[1].PassiveConnectionsSecurity)
	require.Equal(t, 1, bindings[1].ActiveConnectionsSecurity)
	require.True(t, bindings[1].Debug)
}

func TestWebDAVBindingsFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__1__ADDRESS", "127.0.0.1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__1__PORT", "8000")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__1__ENABLE_HTTPS", "0")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__1__TLS_CIPHER_SUITES", "TLS_RSA_WITH_AES_128_CBC_SHA ")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__1__PROXY_ALLOWED", "192.168.10.1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__ADDRESS", "127.0.1.1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__PORT", "9000")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__ENABLE_HTTPS", "1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__MIN_TLS_VERSION", "13")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__CLIENT_AUTH_TYPE", "1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__2__PREFIX", "/dav2")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__1__ADDRESS")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__1__PORT")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__1__ENABLE_HTTPS")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__1__TLS_CIPHER_SUITES")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__1__PROXY_ALLOWED")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__2__ADDRESS")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__2__PORT")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__2__ENABLE_HTTPS")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__2__MIN_TLS_VERSION")
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
	require.Equal(t, 12, bindings[0].MinTLSVersion)
	require.Len(t, bindings[0].TLSCipherSuites, 0)
	require.Empty(t, bindings[0].Prefix)
	require.Equal(t, 8000, bindings[1].Port)
	require.Equal(t, "127.0.0.1", bindings[1].Address)
	require.False(t, bindings[1].EnableHTTPS)
	require.Equal(t, 12, bindings[1].MinTLSVersion)
	require.Equal(t, 0, bindings[1].ClientAuthType)
	require.Len(t, bindings[1].TLSCipherSuites, 1)
	require.Equal(t, "TLS_RSA_WITH_AES_128_CBC_SHA", bindings[1].TLSCipherSuites[0])
	require.Equal(t, "192.168.10.1", bindings[1].ProxyAllowed[0])
	require.Empty(t, bindings[1].Prefix)
	require.Equal(t, 9000, bindings[2].Port)
	require.Equal(t, "127.0.1.1", bindings[2].Address)
	require.True(t, bindings[2].EnableHTTPS)
	require.Equal(t, 13, bindings[2].MinTLSVersion)
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
	os.Setenv("SFTPGO_HTTPD__BINDINGS__1__HIDE_LOGIN_URL", " 1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__1__EXTRA_CSS__0__PATH", "")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__ADDRESS", "127.0.1.1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__PORT", "9000")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__ENABLE_WEB_ADMIN", "0")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__ENABLE_WEB_CLIENT", "0")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__RENDER_OPENAPI", "0")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__ENABLE_HTTPS", "1 ")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__MIN_TLS_VERSION", "13")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__CLIENT_AUTH_TYPE", "1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__TLS_CIPHER_SUITES", " TLS_AES_256_GCM_SHA384 , TLS_CHACHA20_POLY1305_SHA256")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__PROXY_ALLOWED", " 192.168.9.1 , 172.16.25.0/24")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__HIDE_LOGIN_URL", "3")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__WEB_CLIENT_INTEGRATIONS__1__URL", "http://127.0.0.1/")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__WEB_CLIENT_INTEGRATIONS__1__FILE_EXTENSIONS", ".pdf, .txt")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__WEB_CLIENT_INTEGRATIONS__2__URL", "http://127.0.1.1/")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__WEB_CLIENT_INTEGRATIONS__3__FILE_EXTENSIONS", ".jpg, .txt")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__CLIENT_ID", "client id")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__CLIENT_SECRET", "client secret")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__CONFIG_URL", "config url")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__REDIRECT_BASE_URL", "redirect base url")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__USERNAME_FIELD", "preferred_username")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__ROLE_FIELD", "sftpgo_role")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__ENABLED", "true")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__ALLOWED_HOSTS", "*.example.com,*.example.net")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__ALLOWED_HOSTS_ARE_REGEX", "1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__HOSTS_PROXY_HEADERS", "X-Forwarded-Host")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__HTTPS_REDIRECT", "1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__HTTPS_HOST", "www.example.com")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__HTTPS_PROXY_HEADERS__1__KEY", "X-Forwarded-Proto")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__HTTPS_PROXY_HEADERS__1__VALUE", "https")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__STS_SECONDS", "31536000")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__STS_INCLUDE_SUBDOMAINS", "false")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__STS_PRELOAD", "0")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__CONTENT_TYPE_NOSNIFF", "t")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__CONTENT_SECURITY_POLICY", "script-src $NONCE")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__PERMISSIONS_POLICY", "fullscreen=(), geolocation=()")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__CROSS_ORIGIN_OPENER_POLICY", "same-origin")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__EXPECT_CT_HEADER", `max-age=86400, enforce, report-uri="https://foo.example/report"`)
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__EXTRA_CSS__0__PATH", "path1")
	os.Setenv("SFTPGO_HTTPD__BINDINGS__2__EXTRA_CSS__1__PATH", "path2")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__0__ADDRESS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__0__PORT")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__0__TLS_CIPHER_SUITES")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__1__ADDRESS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__1__PORT")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__1__ENABLE_HTTPS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__1__HIDE_LOGIN_URL")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__1__EXTRA_CSS__0__PATH")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__ADDRESS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__PORT")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__ENABLE_HTTPS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__MIN_TLS_VERSION")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__ENABLE_WEB_ADMIN")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__ENABLE_WEB_CLIENT")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__RENDER_OPENAPI")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__CLIENT_AUTH_TYPE")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__TLS_CIPHER_SUITES")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__PROXY_ALLOWED")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__HIDE_LOGIN_URL")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__WEB_CLIENT_INTEGRATIONS__1__URL")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__WEB_CLIENT_INTEGRATIONS__1__FILE_EXTENSIONS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__WEB_CLIENT_INTEGRATIONS__2__URL")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__WEB_CLIENT_INTEGRATIONS__3__FILE_EXTENSIONS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__CLIENT_ID")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__CLIENT_SECRET")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__CONFIG_URL")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__REDIRECT_BASE_URL")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__USERNAME_FIELD")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__OIDC__ROLE_FIELD")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__ENABLED")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__ALLOWED_HOSTS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__ALLOWED_HOSTS_ARE_REGEX")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__HOSTS_PROXY_HEADERS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__HTTPS_REDIRECT")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__HTTPS_HOST")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__HTTPS_PROXY_HEADERS__1__KEY")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__HTTPS_PROXY_HEADERS__1__VALUE")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__STS_SECONDS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__STS_INCLUDE_SUBDOMAINS")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__STS_PRELOAD")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__CONTENT_TYPE_NOSNIFF")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__CONTENT_SECURITY_POLICY")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__PERMISSIONS_POLICY")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__CROSS_ORIGIN_OPENER_POLICY")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__SECURITY__EXPECT_CT_HEADER")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__EXTRA_CSS__0__PATH")
		os.Unsetenv("SFTPGO_HTTPD__BINDINGS__2__EXTRA_CSS__1__PATH")
	})

	configDir := ".."
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	bindings := config.GetHTTPDConfig().Bindings
	require.Len(t, bindings, 3)
	require.Equal(t, 0, bindings[0].Port)
	require.Equal(t, sockPath, bindings[0].Address)
	require.False(t, bindings[0].EnableHTTPS)
	require.Equal(t, 12, bindings[0].MinTLSVersion)
	require.True(t, bindings[0].EnableWebAdmin)
	require.True(t, bindings[0].EnableWebClient)
	require.True(t, bindings[0].RenderOpenAPI)
	require.Len(t, bindings[0].TLSCipherSuites, 1)
	require.Empty(t, bindings[0].OIDC.ConfigURL)
	require.Equal(t, "TLS_AES_128_GCM_SHA256", bindings[0].TLSCipherSuites[0])
	require.Equal(t, 0, bindings[0].HideLoginURL)
	require.False(t, bindings[0].Security.Enabled)
	require.Equal(t, 8000, bindings[1].Port)
	require.Equal(t, "127.0.0.1", bindings[1].Address)
	require.False(t, bindings[1].EnableHTTPS)
	require.Equal(t, 12, bindings[0].MinTLSVersion)
	require.Len(t, bindings[0].ExtraCSS, 0)
	require.True(t, bindings[1].EnableWebAdmin)
	require.True(t, bindings[1].EnableWebClient)
	require.True(t, bindings[1].RenderOpenAPI)
	require.Nil(t, bindings[1].TLSCipherSuites)
	require.Equal(t, 1, bindings[1].HideLoginURL)
	require.Empty(t, bindings[1].OIDC.ClientID)
	require.False(t, bindings[1].Security.Enabled)
	require.Len(t, bindings[1].ExtraCSS, 0)
	require.Equal(t, 9000, bindings[2].Port)
	require.Equal(t, "127.0.1.1", bindings[2].Address)
	require.True(t, bindings[2].EnableHTTPS)
	require.Equal(t, 13, bindings[2].MinTLSVersion)
	require.False(t, bindings[2].EnableWebAdmin)
	require.False(t, bindings[2].EnableWebClient)
	require.False(t, bindings[2].RenderOpenAPI)
	require.Equal(t, 1, bindings[2].ClientAuthType)
	require.Len(t, bindings[2].TLSCipherSuites, 2)
	require.Equal(t, "TLS_AES_256_GCM_SHA384", bindings[2].TLSCipherSuites[0])
	require.Equal(t, "TLS_CHACHA20_POLY1305_SHA256", bindings[2].TLSCipherSuites[1])
	require.Len(t, bindings[2].ProxyAllowed, 2)
	require.Equal(t, "192.168.9.1", bindings[2].ProxyAllowed[0])
	require.Equal(t, "172.16.25.0/24", bindings[2].ProxyAllowed[1])
	require.Equal(t, 3, bindings[2].HideLoginURL)
	require.Len(t, bindings[2].WebClientIntegrations, 1)
	require.Equal(t, "http://127.0.0.1/", bindings[2].WebClientIntegrations[0].URL)
	require.Equal(t, []string{".pdf", ".txt"}, bindings[2].WebClientIntegrations[0].FileExtensions)
	require.Equal(t, "client id", bindings[2].OIDC.ClientID)
	require.Equal(t, "client secret", bindings[2].OIDC.ClientSecret)
	require.Equal(t, "config url", bindings[2].OIDC.ConfigURL)
	require.Equal(t, "redirect base url", bindings[2].OIDC.RedirectBaseURL)
	require.Equal(t, "preferred_username", bindings[2].OIDC.UsernameField)
	require.Equal(t, "sftpgo_role", bindings[2].OIDC.RoleField)
	require.True(t, bindings[2].Security.Enabled)
	require.Len(t, bindings[2].Security.AllowedHosts, 2)
	require.Equal(t, "*.example.com", bindings[2].Security.AllowedHosts[0])
	require.Equal(t, "*.example.net", bindings[2].Security.AllowedHosts[1])
	require.True(t, bindings[2].Security.AllowedHostsAreRegex)
	require.Len(t, bindings[2].Security.HostsProxyHeaders, 1)
	require.Equal(t, "X-Forwarded-Host", bindings[2].Security.HostsProxyHeaders[0])
	require.True(t, bindings[2].Security.HTTPSRedirect)
	require.Equal(t, "www.example.com", bindings[2].Security.HTTPSHost)
	require.Len(t, bindings[2].Security.HTTPSProxyHeaders, 1)
	require.Equal(t, "X-Forwarded-Proto", bindings[2].Security.HTTPSProxyHeaders[0].Key)
	require.Equal(t, "https", bindings[2].Security.HTTPSProxyHeaders[0].Value)
	require.Equal(t, int64(31536000), bindings[2].Security.STSSeconds)
	require.False(t, bindings[2].Security.STSIncludeSubdomains)
	require.False(t, bindings[2].Security.STSPreload)
	require.True(t, bindings[2].Security.ContentTypeNosniff)
	require.Equal(t, "script-src $NONCE", bindings[2].Security.ContentSecurityPolicy)
	require.Equal(t, "fullscreen=(), geolocation=()", bindings[2].Security.PermissionsPolicy)
	require.Equal(t, "same-origin", bindings[2].Security.CrossOriginOpenerPolicy)
	require.Equal(t, `max-age=86400, enforce, report-uri="https://foo.example/report"`, bindings[2].Security.ExpectCTHeader)
	require.Len(t, bindings[2].ExtraCSS, 2)
	require.Equal(t, "path1", bindings[2].ExtraCSS[0].Path)
	require.Equal(t, "path2", bindings[2].ExtraCSS[1].Path)
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

func TestHTTPClientHeadersFromEnv(t *testing.T) {
	reset()

	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	httpConf := config.GetHTTPConfig()
	httpConf.Headers = append(httpConf.Headers, httpclient.Header{
		Key:   "key",
		Value: "value",
		URL:   "url",
	})
	c := make(map[string]httpclient.Config)
	c["http"] = httpConf
	jsonConf, err := json.Marshal(c)
	require.NoError(t, err)
	err = os.WriteFile(configFilePath, jsonConf, os.ModePerm)
	require.NoError(t, err)
	err = config.LoadConfig(configDir, confName)
	require.NoError(t, err)
	require.Len(t, config.GetHTTPConfig().Headers, 1)
	require.Equal(t, "key", config.GetHTTPConfig().Headers[0].Key)
	require.Equal(t, "value", config.GetHTTPConfig().Headers[0].Value)
	require.Equal(t, "url", config.GetHTTPConfig().Headers[0].URL)

	os.Setenv("SFTPGO_HTTP__HEADERS__0__KEY", "key0")
	os.Setenv("SFTPGO_HTTP__HEADERS__0__VALUE", "value0")
	os.Setenv("SFTPGO_HTTP__HEADERS__0__URL", "url0")
	os.Setenv("SFTPGO_HTTP__HEADERS__8__KEY", "key8")
	os.Setenv("SFTPGO_HTTP__HEADERS__9__KEY", "key9")
	os.Setenv("SFTPGO_HTTP__HEADERS__9__VALUE", "value9")
	os.Setenv("SFTPGO_HTTP__HEADERS__9__URL", "url9")

	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_HTTP__HEADERS__0__KEY")
		os.Unsetenv("SFTPGO_HTTP__HEADERS__0__VALUE")
		os.Unsetenv("SFTPGO_HTTP__HEADERS__0__URL")
		os.Unsetenv("SFTPGO_HTTP__HEADERS__8__KEY")
		os.Unsetenv("SFTPGO_HTTP__HEADERS__9__KEY")
		os.Unsetenv("SFTPGO_HTTP__HEADERS__9__VALUE")
		os.Unsetenv("SFTPGO_HTTP__HEADERS__9__URL")
	})

	err = config.LoadConfig(configDir, confName)
	require.NoError(t, err)
	require.Len(t, config.GetHTTPConfig().Headers, 2)
	require.Equal(t, "key0", config.GetHTTPConfig().Headers[0].Key)
	require.Equal(t, "value0", config.GetHTTPConfig().Headers[0].Value)
	require.Equal(t, "url0", config.GetHTTPConfig().Headers[0].URL)
	require.Equal(t, "key9", config.GetHTTPConfig().Headers[1].Key)
	require.Equal(t, "value9", config.GetHTTPConfig().Headers[1].Value)
	require.Equal(t, "url9", config.GetHTTPConfig().Headers[1].URL)

	err = os.Remove(configFilePath)
	assert.NoError(t, err)

	config.Init()

	err = config.LoadConfig(configDir, "")
	require.NoError(t, err)
	require.Len(t, config.GetHTTPConfig().Headers, 2)
	require.Equal(t, "key0", config.GetHTTPConfig().Headers[0].Key)
	require.Equal(t, "value0", config.GetHTTPConfig().Headers[0].Value)
	require.Equal(t, "url0", config.GetHTTPConfig().Headers[0].URL)
	require.Equal(t, "key9", config.GetHTTPConfig().Headers[1].Key)
	require.Equal(t, "value9", config.GetHTTPConfig().Headers[1].Value)
	require.Equal(t, "url9", config.GetHTTPConfig().Headers[1].URL)
}

func TestConfigFromEnv(t *testing.T) {
	reset()

	os.Setenv("SFTPGO_SFTPD__BINDINGS__0__ADDRESS", "127.0.0.1")
	os.Setenv("SFTPGO_WEBDAVD__BINDINGS__0__PORT", "12000")
	os.Setenv("SFTPGO_DATA_PROVIDER__PASSWORD_HASHING__ARGON2_OPTIONS__ITERATIONS", "41")
	os.Setenv("SFTPGO_DATA_PROVIDER__POOL_SIZE", "10")
	os.Setenv("SFTPGO_DATA_PROVIDER__IS_SHARED", "1")
	os.Setenv("SFTPGO_DATA_PROVIDER__ACTIONS__EXECUTE_ON", "add")
	os.Setenv("SFTPGO_KMS__SECRETS__URL", "local")
	os.Setenv("SFTPGO_KMS__SECRETS__MASTER_KEY_PATH", "path")
	os.Setenv("SFTPGO_TELEMETRY__TLS_CIPHER_SUITES", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")
	os.Setenv("SFTPGO_HTTPD__SETUP__INSTALLATION_CODE", "123")
	t.Cleanup(func() {
		os.Unsetenv("SFTPGO_SFTPD__BINDINGS__0__ADDRESS")
		os.Unsetenv("SFTPGO_WEBDAVD__BINDINGS__0__PORT")
		os.Unsetenv("SFTPGO_DATA_PROVIDER__PASSWORD_HASHING__ARGON2_OPTIONS__ITERATIONS")
		os.Unsetenv("SFTPGO_DATA_PROVIDER__POOL_SIZE")
		os.Unsetenv("SFTPGO_DATA_PROVIDER__IS_SHARED")
		os.Unsetenv("SFTPGO_DATA_PROVIDER__ACTIONS__EXECUTE_ON")
		os.Unsetenv("SFTPGO_KMS__SECRETS__URL")
		os.Unsetenv("SFTPGO_KMS__SECRETS__MASTER_KEY_PATH")
		os.Unsetenv("SFTPGO_TELEMETRY__TLS_CIPHER_SUITES")
		os.Unsetenv("SFTPGO_HTTPD__SETUP__INSTALLATION_CODE")
	})
	err := config.LoadConfig(".", "invalid config")
	assert.NoError(t, err)
	sftpdConfig := config.GetSFTPDConfig()
	assert.Equal(t, "127.0.0.1", sftpdConfig.Bindings[0].Address)
	assert.Equal(t, 12000, config.GetWebDAVDConfig().Bindings[0].Port)
	dataProviderConf := config.GetProviderConf()
	assert.Equal(t, uint32(41), dataProviderConf.PasswordHashing.Argon2Options.Iterations)
	assert.Equal(t, 10, dataProviderConf.PoolSize)
	assert.Equal(t, 1, dataProviderConf.IsShared)
	assert.Len(t, dataProviderConf.Actions.ExecuteOn, 1)
	assert.Contains(t, dataProviderConf.Actions.ExecuteOn, "add")
	kmsConfig := config.GetKMSConfig()
	assert.Equal(t, "local", kmsConfig.Secrets.URL)
	assert.Equal(t, "path", kmsConfig.Secrets.MasterKeyPath)
	telemetryConfig := config.GetTelemetryConfig()
	assert.Len(t, telemetryConfig.TLSCipherSuites, 2)
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", telemetryConfig.TLSCipherSuites[0])
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", telemetryConfig.TLSCipherSuites[1])
	assert.Equal(t, "123", config.GetHTTPDConfig().Setup.InstallationCode)
}
