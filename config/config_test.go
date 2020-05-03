package config_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/stretchr/testify/assert"
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
	err = ioutil.WriteFile(configFilePath, []byte("{invalid json}"), 0666)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NotNil(t, err)
	err = ioutil.WriteFile(configFilePath, []byte("{\"sftpd\": {\"bind_port\": \"a\"}}"), 0666)
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
	err = ioutil.WriteFile(configFilePath, jsonConf, 0666)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NoError(t, err)
	sftpdConf = config.GetSFTPDConfig()
	assert.NotEmpty(t, strings.TrimSpace(sftpdConf.Banner))
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestInvalidUploadMode(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.UploadMode = 10
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, 0666)
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
	err = ioutil.WriteFile(configFilePath, jsonConf, 0666)
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
	err = ioutil.WriteFile(configFilePath, jsonConf, 0666)
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
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.ProxyProtocol = 10
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, 0666)
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
	err = ioutil.WriteFile(configFilePath, jsonConf, 0666)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NotNil(t, err)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestHookCompatibity(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configDir, configName)
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.ExternalAuthProgram = "ext_auth_program"
	providerConf.PreLoginProgram = "pre_login_program"
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, err := json.Marshal(c)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, 0666)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	assert.Equal(t, "ext_auth_program", providerConf.ExternalAuthHook)
	assert.Equal(t, "pre_login_program", providerConf.PreLoginHook)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.KeyboardInteractiveProgram = "key_int_program"
	cnf := make(map[string]sftpd.Configuration)
	cnf["sftpd"] = sftpdConf
	jsonConf, err = json.Marshal(cnf)
	assert.NoError(t, err)
	err = ioutil.WriteFile(configFilePath, jsonConf, 0666)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, tempConfigName)
	assert.NoError(t, err)
	sftpdConf = config.GetSFTPDConfig()
	assert.Equal(t, "key_int_program", sftpdConf.KeyboardInteractiveHook)
	err = os.Remove(configFilePath)
	assert.NoError(t, err)
}

func TestSetGetConfig(t *testing.T) {
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.IdleTimeout = 3
	config.SetSFTPDConfig(sftpdConf)
	assert.Equal(t, sftpdConf.IdleTimeout, config.GetSFTPDConfig().IdleTimeout)
	dataProviderConf := config.GetProviderConf()
	dataProviderConf.Host = "test host"
	config.SetProviderConf(dataProviderConf)
	assert.Equal(t, dataProviderConf.Host, config.GetProviderConf().Host)
	httpdConf := config.GetHTTPDConfig()
	httpdConf.BindAddress = "0.0.0.0"
	config.SetHTTPDConfig(httpdConf)
	assert.Equal(t, httpdConf.BindAddress, config.GetHTTPDConfig().BindAddress)
}
