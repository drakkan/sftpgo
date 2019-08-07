package cmd

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/drakkan/sftpgo/api"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	configDirFlag    = "config-dir"
	configDirKey     = "config_dir"
	configFileFlag   = "config-file"
	configFileKey    = "config_file"
	logFilePathFlag  = "log-file-path"
	logFilePathKey   = "log_file_path"
	logMaxSizeFlag   = "log-max-size"
	logMaxSizeKey    = "log_max_size"
	logMaxBackupFlag = "log-max-backups"
	logMaxBackupKey  = "log_max_backups"
	logMaxAgeFlag    = "log-max-age"
	logMaxAgeKey     = "log_max_age"
	logCompressFlag  = "log-compress"
	logCompressKey   = "log_compress"
	logVerboseFlag   = "log-verbose"
	logVerboseKey    = "log_verbose"
)

var (
	configDir     string
	configFile    string
	logFilePath   string
	logMaxSize    int
	logMaxBackups int
	logMaxAge     int
	logCompress   bool
	logVerbose    bool
	testVar       string
	serveCmd      = &cobra.Command{
		Use:   "serve",
		Short: "Start the SFTP Server",
		Long: `To start the SFTP Server with the default values for the command line flags simply use:

sftpgo serve
		
Please take a look at the usage below to customize the startup options`,
		Run: func(cmd *cobra.Command, args []string) {
			startServe()
		},
	}
)

func init() {
	rootCmd.AddCommand(serveCmd)

	viper.SetDefault(configDirKey, ".")
	viper.BindEnv(configDirKey, "SFTPGO_CONFIG_DIR")
	serveCmd.Flags().StringVarP(&configDir, configDirFlag, "c", viper.GetString(configDirKey),
		"Location for SFTPGo config dir. This directory should contain the \"sftpgo\" configuration file or the configured "+
			"config-file and it is used as the base for files with a relative path (eg. the private keys for the SFTP server, "+
			"the SQLite database if you use SQLite as data provider). This flag can be set using SFTPGO_CONFIG_DIR env var too.")
	viper.BindPFlag(configDirKey, serveCmd.Flags().Lookup(configDirFlag))

	viper.SetDefault(configFileKey, config.DefaultConfigName)
	viper.BindEnv(configFileKey, "SFTPGO_CONFIG_FILE")
	serveCmd.Flags().StringVarP(&configFile, configFileFlag, "f", viper.GetString(configFileKey),
		"Name for SFTPGo configuration file. It must be the name of a file stored in config-dir not the absolute path to the "+
			"configuration file. The specified file name must have no extension we automatically load JSON, YAML, TOML, HCL and "+
			"Java properties. Therefore if you set \"sftpgo\" then \"sftpgo.json\", \"sftpgo.yaml\" and so on are searched. "+
			"This flag can be set using SFTPGO_CONFIG_FILE env var too.")
	viper.BindPFlag(configFileKey, serveCmd.Flags().Lookup(configFileFlag))

	viper.SetDefault(logFilePathKey, "sftpgo.log")
	viper.BindEnv(logFilePathKey, "SFTPGO_LOG_FILE_PATH")
	serveCmd.Flags().StringVarP(&logFilePath, logFilePathFlag, "l", viper.GetString(logFilePathKey),
		"Location for the log file. This flag can be set using SFTPGO_LOG_FILE_PATH env var too.")
	viper.BindPFlag(logFilePathKey, serveCmd.Flags().Lookup(logFilePathFlag))

	viper.SetDefault(logMaxSizeKey, 10)
	viper.BindEnv(logMaxSizeKey, "SFTPGO_LOG_MAX_SIZE")
	serveCmd.Flags().IntVarP(&logMaxSize, logMaxSizeFlag, "s", viper.GetInt(logMaxSizeKey),
		"Maximum size in megabytes of the log file before it gets rotated. This flag can be set using SFTPGO_LOG_MAX_SIZE "+
			"env var too.")
	viper.BindPFlag(logMaxSizeKey, serveCmd.Flags().Lookup(logMaxSizeFlag))

	viper.SetDefault(logMaxBackupKey, 5)
	viper.BindEnv(logMaxBackupKey, "SFTPGO_LOG_MAX_BACKUPS")
	serveCmd.Flags().IntVarP(&logMaxBackups, "log-max-backups", "b", viper.GetInt(logMaxBackupKey),
		"Maximum number of old log files to retain. This flag can be set using SFTPGO_LOG_MAX_BACKUPS env var too.")
	viper.BindPFlag(logMaxBackupKey, serveCmd.Flags().Lookup(logMaxBackupFlag))

	viper.SetDefault(logMaxAgeKey, 28)
	viper.BindEnv(logMaxAgeKey, "SFTPGO_LOG_MAX_AGE")
	serveCmd.Flags().IntVarP(&logMaxAge, "log-max-age", "a", viper.GetInt(logMaxAgeKey),
		"Maximum number of days to retain old log files. This flag can be set using SFTPGO_LOG_MAX_AGE env var too.")
	viper.BindPFlag(logMaxAgeKey, serveCmd.Flags().Lookup(logMaxAgeFlag))

	viper.SetDefault(logCompressKey, false)
	viper.BindEnv(logCompressKey, "SFTPGO_LOG_COMPRESS")
	serveCmd.Flags().BoolVarP(&logCompress, logCompressFlag, "z", viper.GetBool(logCompressKey), "Determine if the rotated "+
		"log files should be compressed using gzip. This flag can be set using SFTPGO_LOG_COMPRESS env var too.")
	viper.BindPFlag(logCompressKey, serveCmd.Flags().Lookup(logCompressFlag))

	viper.SetDefault(logVerboseKey, true)
	viper.BindEnv(logVerboseKey, "SFTPGO_LOG_VERBOSE")
	serveCmd.Flags().BoolVarP(&logVerbose, logVerboseFlag, "v", viper.GetBool(logVerboseKey), "Enable verbose logs. "+
		"This flag can be set using SFTPGO_LOG_VERBOSE env var too.")
	viper.BindPFlag(logVerboseKey, serveCmd.Flags().Lookup(logVerboseFlag))
}

func startServe() {
	logLevel := zerolog.DebugLevel
	if !logVerbose {
		logLevel = zerolog.InfoLevel
	}
	logger.InitLogger(logFilePath, logMaxSize, logMaxBackups, logMaxAge, logCompress, logLevel)
	logger.Info(logSender, "starting SFTPGo, config dir: %v, config file: %v, log max size: %v log max backups: %v "+
		"log max age: %v log verbose: %v, log compress: %v", configDir, configFile, logMaxSize, logMaxBackups, logMaxAge,
		logVerbose, logCompress)
	config.LoadConfig(configDir, configFile)
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
