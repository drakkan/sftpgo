// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

var (
	logJournalD     = false
	preserveHomeDir = false
	baseHomeDir     = ""
	subsystemCmd    = &cobra.Command{
		Use:   "startsubsys",
		Short: "Use sftpgo as SFTP file transfer subsystem",
		Long: `In this mode SFTPGo speaks the server side of SFTP protocol to stdout and
expects client requests from stdin.
This mode is not intended to be called directly, but from sshd using the
Subsystem option.
For example adding a line like this one in "/etc/ssh/sshd_config":

Subsystem	sftp	sftpgo startsubsys

Command-line flags should be specified in the Subsystem declaration.
`,
		Run: func(_ *cobra.Command, _ []string) {
			logSender := "startsubsys"
			connectionID := xid.New().String()
			var zeroLogLevel zerolog.Level
			switch logLevel {
			case "info":
				zeroLogLevel = zerolog.InfoLevel
			case "warn":
				zeroLogLevel = zerolog.WarnLevel
			case "error":
				zeroLogLevel = zerolog.ErrorLevel
			default:
				zeroLogLevel = zerolog.DebugLevel
			}
			logger.SetLogTime(logUTCTime)
			if logJournalD {
				logger.InitJournalDLogger(zeroLogLevel)
			} else {
				logger.InitStdErrLogger(zeroLogLevel)
			}
			osUser, err := user.Current()
			if err != nil {
				logger.Error(logSender, connectionID, "unable to get the current user: %v", err)
				os.Exit(1)
			}
			username := osUser.Username
			homedir := osUser.HomeDir
			logger.Info(logSender, connectionID, "starting SFTPGo %v as subsystem, user %q home dir %q config dir %q base home dir %q",
				version.Get(), username, homedir, configDir, baseHomeDir)
			err = config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.Error(logSender, connectionID, "unable to load configuration: %v", err)
				os.Exit(1)
			}
			kmsConfig := config.GetKMSConfig()
			if err := kmsConfig.Initialize(); err != nil {
				logger.Error(logSender, connectionID, "unable to initialize KMS: %v", err)
				os.Exit(1)
			}
			mfaConfig := config.GetMFAConfig()
			err = mfaConfig.Initialize()
			if err != nil {
				logger.Error(logSender, "", "unable to initialize MFA: %v", err)
				os.Exit(1)
			}
			dataProviderConf := config.GetProviderConf()
			if dataProviderConf.Driver == dataprovider.SQLiteDataProviderName || dataProviderConf.Driver == dataprovider.BoltDataProviderName {
				logger.Debug(logSender, connectionID, "data provider %q not supported in subsystem mode, using %q provider",
					dataProviderConf.Driver, dataprovider.MemoryDataProviderName)
				dataProviderConf.Driver = dataprovider.MemoryDataProviderName
				dataProviderConf.Name = ""
			}
			config.SetProviderConf(dataProviderConf)
			err = dataprovider.Initialize(dataProviderConf, configDir, false)
			if err != nil {
				logger.Error(logSender, connectionID, "unable to initialize the data provider: %v", err)
				os.Exit(1)
			}
			if err := plugin.Initialize(config.GetPluginsConfig(), logLevel); err != nil {
				logger.Error(logSender, connectionID, "unable to initialize plugin system: %v", err)
				os.Exit(1)
			}
			smtpConfig := config.GetSMTPConfig()
			err = smtpConfig.Initialize(configDir, false)
			if err != nil {
				logger.Error(logSender, connectionID, "unable to initialize SMTP configuration: %v", err)
				os.Exit(1)
			}
			commonConfig := config.GetCommonConfig()
			// idle connection are managed externally
			commonConfig.IdleTimeout = 0
			config.SetCommonConfig(commonConfig)
			if err := common.Initialize(config.GetCommonConfig(), dataProviderConf.GetShared()); err != nil {
				logger.Error(logSender, connectionID, "%v", err)
				os.Exit(1)
			}
			httpConfig := config.GetHTTPConfig()
			if err := httpConfig.Initialize(configDir); err != nil {
				logger.Error(logSender, connectionID, "unable to initialize http client: %v", err)
				os.Exit(1)
			}
			commandConfig := config.GetCommandConfig()
			if err := commandConfig.Initialize(); err != nil {
				logger.Error(logSender, connectionID, "unable to initialize commands configuration: %v", err)
				os.Exit(1)
			}
			user, err := dataprovider.UserExists(username, "")
			if err == nil {
				if user.HomeDir != filepath.Clean(homedir) && !preserveHomeDir {
					// update the user
					user.HomeDir = filepath.Clean(homedir)
					err = dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSystem, "", "")
					if err != nil {
						logger.Error(logSender, connectionID, "unable to update user %q: %v", username, err)
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
				logger.Debug(logSender, connectionID, "home dir for new user %q", user.HomeDir)
				user.Password = connectionID
				user.Permissions = make(map[string][]string)
				user.Permissions["/"] = []string{dataprovider.PermAny}
				err = dataprovider.AddUser(&user, dataprovider.ActionExecutorSystem, "", "")
				if err != nil {
					logger.Error(logSender, connectionID, "unable to add user %q: %v", username, err)
					os.Exit(1)
				}
			}
			err = user.LoadAndApplyGroupSettings()
			if err != nil {
				logger.Error(logSender, connectionID, "unable to apply group settings for user %q: %v", username, err)
				os.Exit(1)
			}
			err = sftpd.ServeSubSystemConnection(&user, connectionID, os.Stdin, os.Stdout)
			if err != nil && err != io.EOF {
				logger.Warn(logSender, connectionID, "serving subsystem finished with error: %v", err)
				os.Exit(1)
			}
			logger.Info(logSender, connectionID, "serving subsystem finished")
			plugin.Handler.Cleanup()
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

	addConfigFlags(subsystemCmd)

	viper.SetDefault(logLevelKey, defaultLogLevel)
	viper.BindEnv(logLevelKey, "SFTPGO_LOG_LEVEL") //nolint:errcheck
	subsystemCmd.Flags().StringVar(&logLevel, logLevelFlag, viper.GetString(logLevelKey),
		`Set the log level. Supported values:

debug, info, warn, error.

This flag can be set
using SFTPGO_LOG_LEVEL env var too.
`)
	viper.BindPFlag(logLevelKey, subsystemCmd.Flags().Lookup(logLevelFlag)) //nolint:errcheck

	viper.SetDefault(logUTCTimeKey, defaultLogUTCTime)
	viper.BindEnv(logUTCTimeKey, "SFTPGO_LOG_UTC_TIME") //nolint:errcheck
	subsystemCmd.Flags().BoolVar(&logUTCTime, logUTCTimeFlag, viper.GetBool(logUTCTimeKey),
		`Use UTC time for logging. This flag can be set
using SFTPGO_LOG_UTC_TIME env var too.
`)
	viper.BindPFlag(logUTCTimeKey, subsystemCmd.Flags().Lookup(logUTCTimeFlag)) //nolint:errcheck

	rootCmd.AddCommand(subsystemCmd)
}
