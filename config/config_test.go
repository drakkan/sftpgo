package config_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/drakkan/sftpgo/api"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/sftpd"
)

func TestLoadConfigTest(t *testing.T) {
	configDir := ".."
	confName := "sftpgo.conf"
	configFilePath := filepath.Join(configDir, confName)
	err := config.LoadConfig(configFilePath)
	if err != nil {
		t.Errorf("error loading config")
	}
	emptyHTTPDConf := api.HTTPDConf{}
	if config.GetHTTPDConfig() == emptyHTTPDConf {
		t.Errorf("error loading httpd conf")
	}
	emptyProviderConf := dataprovider.Config{}
	if config.GetProviderConf() == emptyProviderConf {
		t.Errorf("error loading provider conf")
	}
	emptySFTPDConf := sftpd.Configuration{}
	if config.GetSFTPDConfig().BindPort == emptySFTPDConf.BindPort {
		t.Errorf("error loading SFTPD conf")
	}
	confName = "sftpgo.conf.missing"
	configFilePath = filepath.Join(configDir, confName)
	err = config.LoadConfig(configFilePath)
	if err == nil {
		t.Errorf("loading a non existent config file must fail")
	}
	ioutil.WriteFile(configFilePath, []byte("{invalid json}"), 0666)
	err = config.LoadConfig(configFilePath)
	if err == nil {
		t.Errorf("loading an invalid config file must fail")
	}
	os.Remove(configFilePath)
}
