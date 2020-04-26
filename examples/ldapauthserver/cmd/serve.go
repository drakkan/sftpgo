package cmd

import (
	"path/filepath"

	"github.com/drakkan/sftpgo/ldapauthserver/config"
	"github.com/drakkan/sftpgo/ldapauthserver/httpd"
	"github.com/drakkan/sftpgo/ldapauthserver/logger"
	"github.com/drakkan/sftpgo/ldapauthserver/utils"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var (
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the LDAP Authentication Server",
		Long: `To start the server with the default values for the command line flags simply use:

ldapauthserver serve

Please take a look at the usage below to customize the startup options`,
		Run: func(cmd *cobra.Command, args []string) {
			startServer()
		},
	}
)

func init() {
	rootCmd.AddCommand(serveCmd)
	addServeFlags(serveCmd)
}

func startServer() error {
	logLevel := zerolog.DebugLevel
	if !logVerbose {
		logLevel = zerolog.InfoLevel
	}
	if !filepath.IsAbs(logFilePath) && utils.IsFileInputValid(logFilePath) {
		logFilePath = filepath.Join(configDir, logFilePath)
	}
	logger.InitLogger(logFilePath, logMaxSize, logMaxBackups, logMaxAge, logCompress, logLevel)
	version := utils.GetAppVersion()
	logger.Info(logSender, "", "starting LDAP Auth Server %v, config dir: %v, config file: %v, log max size: %v log max backups: %v "+
		"log max age: %v log verbose: %v, log compress: %v", version.GetVersionAsString(), configDir, configFile, logMaxSize,
		logMaxBackups, logMaxAge, logVerbose, logCompress)
	config.LoadConfig(configDir, configFile)
	return httpd.StartHTTPServer(configDir, config.GetHTTPDConfig())
}
