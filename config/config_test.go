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
)

const (
	tempConfigName = "temp"
)

func TestLoadConfigTest(t *testing.T) {
	configDir := ".."
	err := config.LoadConfig(configDir, "")
	if err != nil {
		t.Errorf("error loading config")
	}
	emptyHTTPDConf := httpd.Conf{}
	if config.GetHTTPDConfig() == emptyHTTPDConf {
		t.Errorf("error loading httpd conf")
	}
	emptyProviderConf := dataprovider.Config{}
	if config.GetProviderConf().Driver == emptyProviderConf.Driver {
		t.Errorf("error loading provider conf")
	}
	emptySFTPDConf := sftpd.Configuration{}
	if config.GetSFTPDConfig().BindPort == emptySFTPDConf.BindPort {
		t.Errorf("error loading SFTPD conf")
	}
	emptyHTTPConfig := httpclient.Config{}
	if config.GetHTTPConfig().Timeout == emptyHTTPConfig.Timeout {
		t.Errorf("error loading HTTP conf")
	}
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	err = config.LoadConfig(configDir, tempConfigName)
	if err == nil {
		t.Errorf("loading a non existent config file must fail")
	}
	ioutil.WriteFile(configFilePath, []byte("{invalid json}"), 0666)
	err = config.LoadConfig(configDir, tempConfigName)
	if err == nil {
		t.Errorf("loading an invalid config file must fail")
	}
	ioutil.WriteFile(configFilePath, []byte("{\"sftpd\": {\"bind_port\": \"a\"}}"), 0666)
	err = config.LoadConfig(configDir, tempConfigName)
	if err == nil {
		t.Errorf("loading a config with an invalid bond_port must fail")
	}
	os.Remove(configFilePath)
}

func TestEmptyBanner(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	config.LoadConfig(configDir, "")
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Banner = " "
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, _ := json.Marshal(c)
	err := ioutil.WriteFile(configFilePath, jsonConf, 0666)
	if err != nil {
		t.Errorf("error saving temporary configuration")
	}
	config.LoadConfig(configDir, tempConfigName)
	sftpdConf = config.GetSFTPDConfig()
	if strings.TrimSpace(sftpdConf.Banner) == "" {
		t.Errorf("SFTPD banner cannot be empty")
	}
	os.Remove(configFilePath)
}

func TestInvalidUploadMode(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	config.LoadConfig(configDir, "")
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.UploadMode = 10
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, _ := json.Marshal(c)
	err := ioutil.WriteFile(configFilePath, jsonConf, 0666)
	if err != nil {
		t.Errorf("error saving temporary configuration")
	}
	err = config.LoadConfig(configDir, tempConfigName)
	if err == nil {
		t.Errorf("Loading configuration with invalid upload_mode must fail")
	}
	os.Remove(configFilePath)
}

func TestInvalidExternalAuthScope(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	providerConf.ExternalAuthScope = 10
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, _ := json.Marshal(c)
	err := ioutil.WriteFile(configFilePath, jsonConf, 0666)
	if err != nil {
		t.Errorf("error saving temporary configuration")
	}
	err = config.LoadConfig(configDir, tempConfigName)
	if err == nil {
		t.Errorf("Loading configuration with invalid external_auth_scope must fail")
	}
	os.Remove(configFilePath)
}

func TestInvalidCredentialsPath(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	providerConf.CredentialsPath = ""
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, _ := json.Marshal(c)
	err := ioutil.WriteFile(configFilePath, jsonConf, 0666)
	if err != nil {
		t.Errorf("error saving temporary configuration")
	}
	err = config.LoadConfig(configDir, tempConfigName)
	if err == nil {
		t.Errorf("Loading configuration with credentials path must fail")
	}
	os.Remove(configFilePath)
}

func TestInvalidProxyProtocol(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	config.LoadConfig(configDir, "")
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.ProxyProtocol = 10
	c := make(map[string]sftpd.Configuration)
	c["sftpd"] = sftpdConf
	jsonConf, _ := json.Marshal(c)
	err := ioutil.WriteFile(configFilePath, jsonConf, 0666)
	if err != nil {
		t.Errorf("error saving temporary configuration")
	}
	err = config.LoadConfig(configDir, tempConfigName)
	if err == nil {
		t.Errorf("Loading configuration with invalid proxy_protocol must fail")
	}
	os.Remove(configFilePath)
}

func TestInvalidUsersBaseDir(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	providerConf.UsersBaseDir = "."
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, _ := json.Marshal(c)
	err := ioutil.WriteFile(configFilePath, jsonConf, 0666)
	if err != nil {
		t.Errorf("error saving temporary configuration")
	}
	err = config.LoadConfig(configDir, tempConfigName)
	if err == nil {
		t.Errorf("Loading configuration with invalid users base dir must fail")
	}
	os.Remove(configFilePath)
}

func TestHookCompatibity(t *testing.T) {
	configDir := ".."
	confName := tempConfigName + ".json"
	configFilePath := filepath.Join(configDir, confName)
	config.LoadConfig(configDir, "")
	providerConf := config.GetProviderConf()
	providerConf.ExternalAuthProgram = "ext_auth_program"
	providerConf.PreLoginProgram = "pre_login_program"
	c := make(map[string]dataprovider.Config)
	c["data_provider"] = providerConf
	jsonConf, _ := json.Marshal(c)
	err := ioutil.WriteFile(configFilePath, jsonConf, 0666)
	if err != nil {
		t.Errorf("error saving temporary configuration")
	}
	config.LoadConfig(configDir, tempConfigName)
	providerConf = config.GetProviderConf()
	if providerConf.ExternalAuthHook != "ext_auth_program" {
		t.Error("unexpected external auth hook")
	}
	if providerConf.PreLoginHook != "pre_login_program" {
		t.Error("unexpected pre-login hook")
	}
	os.Remove(configFilePath)

	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.KeyboardInteractiveProgram = "key_int_program"
	cnf := make(map[string]sftpd.Configuration)
	cnf["sftpd"] = sftpdConf
	jsonConf, _ = json.Marshal(cnf)
	err = ioutil.WriteFile(configFilePath, jsonConf, 0666)
	if err != nil {
		t.Errorf("error saving temporary configuration")
	}
	config.LoadConfig(configDir, tempConfigName)
	sftpdConf = config.GetSFTPDConfig()
	if sftpdConf.KeyboardInteractiveHook != "key_int_program" {
		t.Error("unexpected keyboard interactive hook")
	}
	os.Remove(configFilePath)
}

func TestSetGetConfig(t *testing.T) {
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.IdleTimeout = 3
	config.SetSFTPDConfig(sftpdConf)
	if config.GetSFTPDConfig().IdleTimeout != sftpdConf.IdleTimeout {
		t.Errorf("set sftpd conf failed")
	}
	dataProviderConf := config.GetProviderConf()
	dataProviderConf.Host = "test host"
	config.SetProviderConf(dataProviderConf)
	if config.GetProviderConf().Host != dataProviderConf.Host {
		t.Errorf("set data provider conf failed")
	}
	httpdConf := config.GetHTTPDConfig()
	httpdConf.BindAddress = "0.0.0.0"
	config.SetHTTPDConfig(httpdConf)
	if config.GetHTTPDConfig().BindAddress != httpdConf.BindAddress {
		t.Errorf("set httpd conf failed")
	}
}
