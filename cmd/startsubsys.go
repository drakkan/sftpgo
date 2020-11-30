package cmd

import (
	"io"
	"os"
	"os/user"
	"path/filepath"

	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/version"
)

var (
	logJournalD     = false
	preserveHomeDir = false
	baseHomeDir     = ""
	subsystemCmd    = &cobra.Command{
		Use:   "startsubsys",
		Short: "Use SFTPGo as SFTP file transfer subsystem",
		Long: `In this mode SFTPGo speaks the server side of SFTP protocol to stdout and
expects client requests from stdin.
This mode is not intended to be called directly, but from sshd using the
Subsystem option.
For example adding a line like this one in "/etc/ssh/sshd_config":

Subsystem	sftp	sftpgo startsubsys

Command-line flags should be specified in the Subsystem declaration.
`,
		Run: func(cmd *cobra.Command, args []string) {
			logSender := "startsubsys"
			connectionID := xid.New().String()
			logLevel := zerolog.DebugLevel
			if !logVerbose {
				logLevel = zerolog.InfoLevel
			}
			if logJournalD {
				logger.InitJournalDLogger(logLevel)
			} else {
				logger.InitStdErrLogger(logLevel)
			}
			osUser, err := user.Current()
			if err != nil {
				logger.Error(logSender, connectionID, "unable to get the current user: %v", err)
				os.Exit(1)
			}
			username := osUser.Username
			homedir := osUser.HomeDir
			logger.Info(logSender, connectionID, "starting SFTPGo %v as subsystem, user %#v home dir %#v config dir %#v base home dir %#v",
				version.Get(), username, homedir, configDir, baseHomeDir)
			err = config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.Error(logSender, connectionID, "unable to load configuration: %v", err)
				os.Exit(1)
			}
			commonConfig := config.GetCommonConfig()
			// idle connection are managed externally
			commonConfig.IdleTimeout = 0
			config.SetCommonConfig(commonConfig)
			common.Initialize(config.GetCommonConfig())
			dataProviderConf := config.GetProviderConf()
			if dataProviderConf.Driver == dataprovider.SQLiteDataProviderName || dataProviderConf.Driver == dataprovider.BoltDataProviderName {
				logger.Debug(logSender, connectionID, "data provider %#v not supported in subsystem mode, using %#v provider",
					dataProviderConf.Driver, dataprovider.MemoryDataProviderName)
				dataProviderConf.Driver = dataprovider.MemoryDataProviderName
				dataProviderConf.Name = ""
				dataProviderConf.PreferDatabaseCredentials = true
			}
			config.SetProviderConf(dataProviderConf)
			err = dataprovider.Initialize(dataProviderConf, configDir)
			if err != nil {
				logger.Error(logSender, connectionID, "unable to initialize the data provider: %v", err)
				os.Exit(1)
			}
			httpConfig := config.GetHTTPConfig()
			httpConfig.Initialize(configDir)
			kmsConfig := config.GetKMSConfig()
			if err := kmsConfig.Initialize(); err != nil {
				logger.Error(logSender, connectionID, "unable to initialize KMS: %v", err)
				os.Exit(1)
			}
			user, err := dataprovider.UserExists(username)
			if err == nil {
				if user.HomeDir != filepath.Clean(homedir) && !preserveHomeDir {
					// update the user
					user.HomeDir = filepath.Clean(homedir)
					err = dataprovider.UpdateUser(user)
					if err != nil {
						logger.Error(logSender, connectionID, "unable to update user %#v: %v", username, err)
						os.Exit(1)
					}
				}
			} else {
				user.Username = username
				if baseHomeDir != "" && filepath.IsAbs(baseHomeDir) {
					user.HomeDir = filepath.Join(baseHomeDir, username)
				} else {
					user.HomeDir = filepath.Clean(homedir)
				}
				logger.Debug(logSender, connectionID, "home dir for new user %#v", user.HomeDir)
				user.Password = connectionID
				user.Permissions = make(map[string][]string)
				user.Permissions["/"] = []string{dataprovider.PermAny}
				err = dataprovider.AddUser(user)
				if err != nil {
					logger.Error(logSender, connectionID, "unable to add user %#v: %v", username, err)
					os.Exit(1)
				}
			}
			err = sftpd.ServeSubSystemConnection(user, connectionID, os.Stdin, os.Stdout)
			if err != nil && err != io.EOF {
				logger.Warn(logSender, connectionID, "serving subsystem finished with error: %v", err)
				os.Exit(1)
			}
			logger.Info(logSender, connectionID, "serving subsystem finished")
			os.Exit(0)
		},
	}
)

func init() {
	subsystemCmd.Flags().BoolVarP(&preserveHomeDir, "preserve-home", "p", false, `If the user already exists, the existing home
directory will not be changed`)
	subsystemCmd.Flags().StringVarP(&baseHomeDir, "base-home-dir", "d", "", `If the user does not exist specify an alternate
starting directory. The home directory for a new
user will be:

[base-home-dir]/[username]

base-home-dir must be an absolute path.`)
	subsystemCmd.Flags().BoolVarP(&logJournalD, "log-to-journald", "j", false, `Send logs to journald. Only available on Linux.
Use:

$ journalctl -o verbose -f

To see full logs.
If not set, the logs will be sent to the standard
error`)
	viper.SetDefault(configDirKey, defaultConfigDir)
	viper.BindEnv(configDirKey, "SFTPGO_CONFIG_DIR") //nolint:errcheck // err is not nil only if the key to bind is missing
	subsystemCmd.Flags().StringVarP(&configDir, configDirFlag, "c", viper.GetString(configDirKey),
		`Location for SFTPGo config dir. This directory
should contain the "sftpgo" configuration file
or the configured config-file and it is used as
the base for files with a relative path (eg. the
private keys for the SFTP server, the SQLite
database if you use SQLite as data provider).
This flag can be set using SFTPGO_CONFIG_DIR
env var too.`)
	viper.BindPFlag(configDirKey, subsystemCmd.Flags().Lookup(configDirFlag)) //nolint:errcheck

	viper.SetDefault(configFileKey, defaultConfigName)
	viper.BindEnv(configFileKey, "SFTPGO_CONFIG_FILE") //nolint:errcheck
	subsystemCmd.Flags().StringVarP(&configFile, configFileFlag, "f", viper.GetString(configFileKey),
		`Name for SFTPGo configuration file. It must be
the name of a file stored in config-dir not the
absolute path to the configuration file. The
specified file name must have no extension we
automatically load JSON, YAML, TOML, HCL and
Java properties. Therefore if you set "sftpgo"
then "sftpgo.json", "sftpgo.yaml" and so on
are searched.
This flag can be set using SFTPGO_CONFIG_FILE
env var too.`)
	viper.BindPFlag(configFileKey, subsystemCmd.Flags().Lookup(configFileFlag)) //nolint:errcheck

	viper.SetDefault(logVerboseKey, defaultLogVerbose)
	viper.BindEnv(logVerboseKey, "SFTPGO_LOG_VERBOSE") //nolint:errcheck
	subsystemCmd.Flags().BoolVarP(&logVerbose, logVerboseFlag, "v", viper.GetBool(logVerboseKey),
		`Enable verbose logs. This flag can be set
using SFTPGO_LOG_VERBOSE env var too.
`)
	viper.BindPFlag(logVerboseKey, subsystemCmd.Flags().Lookup(logVerboseFlag)) //nolint:errcheck

	rootCmd.AddCommand(subsystemCmd)
}
