// +build !noportable

package service

import (
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/grandcat/zeroconf"

	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/version"
)

// StartPortableMode starts the service in portable mode
func (s *Service) StartPortableMode(sftpdPort int, enabledSSHCommands []string, advertiseService, advertiseCredentials bool) error {
	if s.PortableMode != 1 {
		return fmt.Errorf("service is not configured for portable mode")
	}
	var err error
	rand.Seed(time.Now().UnixNano())
	if len(s.PortableUser.Username) == 0 {
		s.PortableUser.Username = "user"
	}
	if len(s.PortableUser.PublicKeys) == 0 && len(s.PortableUser.Password) == 0 {
		var b strings.Builder
		for i := 0; i < 8; i++ {
			b.WriteRune(chars[rand.Intn(len(chars))])
		}
		s.PortableUser.Password = b.String()
	}
	dataProviderConf := config.GetProviderConf()
	dataProviderConf.Driver = dataprovider.MemoryDataProviderName
	dataProviderConf.Name = ""
	dataProviderConf.CredentialsPath = filepath.Join(os.TempDir(), "credentials")
	config.SetProviderConf(dataProviderConf)
	httpdConf := config.GetHTTPDConfig()
	httpdConf.BindPort = 0
	config.SetHTTPDConfig(httpdConf)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.MaxAuthTries = 12
	if sftpdPort > 0 {
		sftpdConf.BindPort = sftpdPort
	} else {
		// dynamic ports starts from 49152
		sftpdConf.BindPort = 49152 + rand.Intn(15000)
	}
	if utils.IsStringInSlice("*", enabledSSHCommands) {
		sftpdConf.EnabledSSHCommands = sftpd.GetSupportedSSHCommands()
	} else {
		sftpdConf.EnabledSSHCommands = enabledSSHCommands
	}
	config.SetSFTPDConfig(sftpdConf)

	err = s.Start()
	if err != nil {
		return err
	}
	var mDNSService *zeroconf.Server
	if advertiseService {
		meta := []string{
			fmt.Sprintf("version=%v", version.GetAsString()),
		}
		if advertiseCredentials {
			logger.InfoToConsole("Advertising credentials via multicast DNS")
			meta = append(meta, fmt.Sprintf("user=%v", s.PortableUser.Username))
			if len(s.PortableUser.Password) > 0 {
				meta = append(meta, fmt.Sprintf("password=%v", s.PortableUser.Password))
			} else {
				logger.InfoToConsole("Unable to advertise key based credentials via multicast DNS, we don't have the private key")
			}
		}
		mDNSService, err = zeroconf.Register(
			fmt.Sprintf("SFTPGo portable %v", sftpdConf.BindPort), // service instance name
			"_sftp-ssh._tcp",   // service type and protocol
			"local.",           // service domain
			sftpdConf.BindPort, // service port
			meta,               // service metadata
			nil,                // register on all network interfaces
		)
		if err != nil {
			mDNSService = nil
			logger.WarnToConsole("Unable to advertise SFTP service via multicast DNS: %v", err)
		} else {
			logger.InfoToConsole("SFTP service advertised via multicast DNS")
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		if mDNSService != nil {
			logger.InfoToConsole("unregistering multicast DNS service")
			mDNSService.Shutdown()
		}
		s.Stop()
	}()

	logger.InfoToConsole("Portable mode ready, SFTP port: %v, user: %#v, password: %#v, public keys: %v, directory: %#v, "+
		"permissions: %+v, enabled ssh commands: %v file extensions filters: %+v", sftpdConf.BindPort, s.PortableUser.Username,
		s.PortableUser.Password, s.PortableUser.PublicKeys, s.getPortableDirToServe(), s.PortableUser.Permissions,
		sftpdConf.EnabledSSHCommands, s.PortableUser.Filters.FileExtensions)
	return nil
}

func (s *Service) getPortableDirToServe() string {
	var dirToServe string
	if s.PortableUser.FsConfig.Provider == 1 {
		dirToServe = s.PortableUser.FsConfig.S3Config.KeyPrefix
	} else if s.PortableUser.FsConfig.Provider == 2 {
		dirToServe = s.PortableUser.FsConfig.GCSConfig.KeyPrefix
	} else {
		dirToServe = s.PortableUser.HomeDir
	}
	return dirToServe
}
