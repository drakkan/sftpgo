package config_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/ftpd"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
)

const (
	tempConfigName = "temp"
	configName     = "sftpgo"
)

func TestLoadConfigTest(t *testing.T) {
	configDir := ".."
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	assert.NotEqual(t, httpd.Conf{}, config.GetHTTPConfig())
	assert.NotEqual(t, dataprovider.Config{}, config.GetProviderConf())
	assert.NotEqual(t, sftpd.Configuration{}, config.GetSFTPDConfig())
	assert.NotEqual(t, httpclient.Config{}, config.GetHTTPConfig())
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NotNil(t, err)
	err = ioutil.WriteFile(configFilePath, []byte("{invalid json}"), os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NotNil(t, err)
	err = ioutil.WriteFile(configFilePath, []byte("{\"sftpd\": {\"bind_port\": \"a\"}}"), os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NotNil(t, err)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestEmptyBanner(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Banner = " "
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, _ := json.Marshal(c)
	err = ioutil.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
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
	err = ioutil.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NoError(t, err)
	ftpdConf = config.GetFTPDConfig()
	assert.NotEmpty(t, strings.TrimSpace(ftpdConf.Banner))
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidUploadMode(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	commonConf := config.GetCommonConfig()
	commonConf.UploadMode = 10
	c := make(map[string]common.Configuration)
	c["common"] = commonConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NotNil(t, err)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidExternalAuthScope(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.ExternalAuthScope = 10
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NotNil(t, err)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidCredentialsPath(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.CredentialsPath = ""
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NotNil(t, err)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidProxyProtocol(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	commonConf := config.GetCommonConfig()
	commonConf.ProxyProtocol = 10
	c := make(map[string]common.Configuration)
	c["common"] = commonConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NotNil(t, err)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidUsersBaseDir(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.UsersBaseDir = "."
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NotNil(t, err)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestCommonParamsCompatibility(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.IdleTimeout = 21 //nolint:staticcheck
	sftpdConf.Actions.Hook = "http://hook"
	sftpdConf.Actions.ExecuteOn = []string{"upload"}
	sftpdConf.SetstatMode = 1                                //nolint:staticcheck
	sftpdConf.UploadMode = common.UploadModeAtomicWithResume //nolint:staticcheck
	sftpdConf.ProxyProtocol = 1                              //nolint:staticcheck
	sftpdConf.ProxyAllowed = []string{"192.168.1.1"}         //nolint:staticcheck
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NoError(t, err)
	commonConf := config.GetCommonConfig()
	assert.Equal(t, 21, commonConf.IdleTimeout)
	assert.Equal(t, "http://hook", commonConf.Actions.Hook)
	assert.Len(t, commonConf.Actions.ExecuteOn, 1)
	assert.True(t, utils.IsStringInSlice("upload", commonConf.Actions.ExecuteOn))
	assert.Equal(t, 1, commonConf.SetstatMode)
	assert.Equal(t, 1, commonConf.ProxyProtocol)
	assert.Len(t, commonConf.ProxyAllowed, 1)
	assert.True(t, utils.IsStringInSlice("192.168.1.1", commonConf.ProxyAllowed))
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestHostKeyCompatibility(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Keys = []sftpd.Key{ //nolint:staticcheck
		{
			PrivateKey: "rsa",
		},
		{
			PrivateKey: "ecdsa",
		},
	}
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, os.ModePerm)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NoError(t, err)
	sftpdConf = config.GetSFTPDConfig()
	assert.Equal(t, 2, len(sftpdConf.HostKeys))
	assert.True(t, utils.IsStringInSlice("rsa", sftpdConf.HostKeys))
	assert.True(t, utils.IsStringInSlice("ecdsa", sftpdConf.HostKeys))
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestSetGetConfig(t *testing.T) {
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.MaxAuthTries = 10
	config.SetSFTPDConfig(sftpdConf)
	assert.Equal(t, sftpdConf.MaxAuthTries, config.GetSFTPDConfig().MaxAuthTries)
	dataProviderConf := config.GetProviderConf()
	dataProviderConf.Host = "test host"
	config.SetProviderConf(dataProviderConf)
	assert.Equal(t, dataProviderConf.Host, config.GetProviderConf().Host)
	httpdConf := config.GetHTTPDConfig()
	httpdConf.BindAddress = "0.0.0.0"
	config.SetHTTPDConfig(httpdConf)
	assert.Equal(t, httpdConf.BindAddress, config.GetHTTPDConfig().BindAddress)
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
}
