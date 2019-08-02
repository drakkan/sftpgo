// Full featured and highly configurable SFTP server.
// For more details about features, installation, configuration and usage please refer to the README inside the source tree:
// https://github.com/drakkan/sftpgo/blob/master/README.md
package main // import "github.com/drakkan/sftpgo"

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"github.com/drakkan/sftpgo/api"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"

	"github.com/rs/zerolog"
)

func main() {
	logSender := "main"
	var (
		configDir      string
		configFileName string
		logFilePath    string
		logMaxSize     int
		logMaxBackups  int
		logMaxAge      int
		logCompress    bool
		logVerbose     bool
	)
	flag.StringVar(&configDir, "config-dir", utils.GetEnvVar("SFTPGO_CONFIG_DIR", "."), "Location for SFTPGo config dir. It must contain "+
		"sftpgo.conf or the configured config-file-name and it is used as the base for files with a relative path (eg. the private "+
		"keys for the SFTP server, the SQLite database if you use SQLite as data provider).")
	flag.StringVar(&configFileName, "config-file-name", utils.GetEnvVar("SFTPGO_CONFIG_FILE_NAME", "sftpgo.conf"), "Name for SFTPGo "+
		"configuration file. It must be the name of a file stored in config-dir not the absolute path to the configuration file")
	flag.StringVar(&logFilePath, "log-file-path", utils.GetEnvVar("SFTPGO_LOG_FILE_PATH", "sftpgo.log"), "Location for the log file")
	flag.IntVar(&logMaxSize, "log-max-size", utils.GetEnvVarAsInt("SFTPGO_LOG_MAX_SIZE", 10), "Maximum size in megabytes of the log file "+
		"before it gets rotated.")
	flag.IntVar(&logMaxBackups, "log-max-backups", utils.GetEnvVarAsInt("SFTPGO_LOG_MAX_BACKUPS", 5), "Maximum number of old log files "+
		"to retain")
	flag.IntVar(&logMaxAge, "log-max-age", utils.GetEnvVarAsInt("SFTPGO_LOG_MAX_AGE", 28), "Maximum number of days to retain old log files")
	flag.BoolVar(&logCompress, "log-compress", utils.GetEnvVarAsInt("SFTPGO_LOG_COMPRESS", 0) > 0, "Determine if the rotated log files "+
		"should be compressed using gzip")
	flag.BoolVar(&logVerbose, "log-verbose", utils.GetEnvVarAsInt("SFTPGO_LOG_VERBOSE", 1) > 0, "Enable verbose logs")
	flag.Parse()

	configFilePath := filepath.Join(configDir, configFileName)
	logLevel := zerolog.DebugLevel
	if !logVerbose {
		logLevel = zerolog.InfoLevel
	}
	logger.InitLogger(logFilePath, logMaxSize, logMaxBackups, logMaxAge, logCompress, logLevel)
	logger.Info(logSender, "starting SFTPGo, config dir: %v", configDir)
	config.LoadConfig(configFilePath)
	providerConf := config.GetProviderConf()

	err := dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		logger.Error(logSender, "error initializing data provider: %v", err)
		logger.ErrorToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}

	dataProvider := dataprovider.GetProvider()
	sftpdConf := config.GetSFTPDConfig()
	httpdConf := config.GetHTTPDConfig()

	sftpd.SetDataProvider(dataProvider)

	shutdown := make(chan bool)

	go func() {
		logger.Debug(logSender, "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.Error(logSender, "could not start SFTP server: %v", err)
			logger.ErrorToConsole("could not start SFTP server: %v", err)
		}
		shutdown <- true
	}()

	if httpdConf.BindPort > 0 {
		router := api.GetHTTPRouter()
		api.SetDataProvider(dataProvider)

		go func() {
			logger.Debug(logSender, "initializing HTTP server with config %+v", httpdConf)
			s := &http.Server{
				Addr:           fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort),
				Handler:        router,
				ReadTimeout:    300 * time.Second,
				WriteTimeout:   300 * time.Second,
				MaxHeaderBytes: 1 << 20, // 1MB
			}
			if err := s.ListenAndServe(); err != nil {
				logger.Error(logSender, "could not start HTTP server: %v", err)
				logger.ErrorToConsole("could not start HTTP server: %v", err)
			}
			shutdown <- true
		}()
	} else {
		logger.Debug(logSender, "HTTP server not started, disabled in config file")
		logger.DebugToConsole("HTTP server not started, disabled in config file")
	}

	<-shutdown
}
