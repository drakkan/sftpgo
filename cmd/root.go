// Package cmd provides Command Line Interface support
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/drakkan/sftpgo/v2/version"
)

const (
	configDirFlag            = "config-dir"
	configDirKey             = "config_dir"
	configFileFlag           = "config-file"
	configFileKey            = "config_file"
	logFilePathFlag          = "log-file-path"
	logFilePathKey           = "log_file_path"
	logMaxSizeFlag           = "log-max-size"
	logMaxSizeKey            = "log_max_size"
	logMaxBackupFlag         = "log-max-backups"
	logMaxBackupKey          = "log_max_backups"
	logMaxAgeFlag            = "log-max-age"
	logMaxAgeKey             = "log_max_age"
	logCompressFlag          = "log-compress"
	logCompressKey           = "log_compress"
	logVerboseFlag           = "log-verbose"
	logVerboseKey            = "log_verbose"
	logUTCTimeFlag           = "log-utc-time"
	logUTCTimeKey            = "log_utc_time"
	loadDataFromFlag         = "loaddata-from"
	loadDataFromKey          = "loaddata_from"
	loadDataModeFlag         = "loaddata-mode"
	loadDataModeKey          = "loaddata_mode"
	loadDataQuotaScanFlag    = "loaddata-scan"
	loadDataQuotaScanKey     = "loaddata_scan"
	loadDataCleanFlag        = "loaddata-clean"
	loadDataCleanKey         = "loaddata_clean"
	defaultConfigDir         = "."
	defaultConfigFile        = ""
	defaultLogFile           = "sftpgo.log"
	defaultLogMaxSize        = 10
	defaultLogMaxBackup      = 5
	defaultLogMaxAge         = 28
	defaultLogCompress       = false
	defaultLogVerbose        = true
	defaultLogUTCTime        = false
	defaultLoadDataFrom      = ""
	defaultLoadDataMode      = 1
	defaultLoadDataQuotaScan = 0
	defaultLoadDataClean     = false
)

var (
	configDir         string
	configFile        string
	logFilePath       string
	logMaxSize        int
	logMaxBackups     int
	logMaxAge         int
	logCompress       bool
	logVerbose        bool
	logUTCTime        bool
	loadDataFrom      string
	loadDataMode      int
	loadDataQuotaScan int
	loadDataClean     bool

	rootCmd = &cobra.Command{
		Use:   "sftpgo",
		Short: "Fully featured and highly configurable SFTP server",
	}
)

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().BoolP("version", "v", false, "")
	rootCmd.Version = version.GetAsString()
	rootCmd.SetVersionTemplate(`{{printf "SFTPGo "}}{{printf "%s" .Version}}
`)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func addConfigFlags(cmd *cobra.Command) {
	viper.SetDefault(configDirKey, defaultConfigDir)
	viper.BindEnv(configDirKey, "SFTPGO_CONFIG_DIR") //nolint:errcheck // err is not nil only if the key to bind is missing
	cmd.Flags().StringVarP(&configDir, configDirFlag, "c", viper.GetString(configDirKey),
		`Location for the config dir. This directory
is used as the base for files with a relative
path, eg. the private keys for the SFTP
server or the SQLite database if you use
SQLite as data provider.
The configuration file, if not explicitly set,
is looked for in this dir. We support reading
from JSON, TOML, YAML, HCL, envfile and Java
properties config files. The default config
file name is "sftpgo" and therefore
"sftpgo.json", "sftpgo.yaml" and so on are
searched.
This flag can be set using SFTPGO_CONFIG_DIR
env var too.`)
	viper.BindPFlag(configDirKey, cmd.Flags().Lookup(configDirFlag)) //nolint:errcheck

	viper.SetDefault(configFileKey, defaultConfigFile)
	viper.BindEnv(configFileKey, "SFTPGO_CONFIG_FILE") //nolint:errcheck
	cmd.Flags().StringVar(&configFile, configFileFlag, viper.GetString(configFileKey),
		`Path to SFTPGo configuration file.
This flag explicitly defines the path, name
and extension of the config file. If must be
an absolute path or a path relative to the
configuration directory. The specified file
name must have a supported extension (JSON,
YAML, TOML, HCL or Java properties).
This flag can be set using SFTPGO_CONFIG_FILE
env var too.`)
	viper.BindPFlag(configFileKey, cmd.Flags().Lookup(configFileFlag)) //nolint:errcheck
}

func addBaseLoadDataFlags(cmd *cobra.Command) {
	viper.SetDefault(loadDataFromKey, defaultLoadDataFrom)
	viper.BindEnv(loadDataFromKey, "SFTPGO_LOADDATA_FROM") //nolint:errcheck
	cmd.Flags().StringVar(&loadDataFrom, loadDataFromFlag, viper.GetString(loadDataFromKey),
		`Load users and folders from this file.
The file must be specified as absolute path
and it must contain a backup obtained using
the "dumpdata" REST API or compatible content.
This flag can be set using SFTPGO_LOADDATA_FROM
env var too.
`)
	viper.BindPFlag(loadDataFromKey, cmd.Flags().Lookup(loadDataFromFlag)) //nolint:errcheck

	viper.SetDefault(loadDataModeKey, defaultLoadDataMode)
	viper.BindEnv(loadDataModeKey, "SFTPGO_LOADDATA_MODE") //nolint:errcheck
	cmd.Flags().IntVar(&loadDataMode, loadDataModeFlag, viper.GetInt(loadDataModeKey),
		`Restore mode for data to load:
  0 - new users are added, existing users are
      updated
  1 - New users are added, existing users are
	  not modified
This flag can be set using SFTPGO_LOADDATA_MODE
env var too.
`)
	viper.BindPFlag(loadDataModeKey, cmd.Flags().Lookup(loadDataModeFlag)) //nolint:errcheck

	viper.SetDefault(loadDataCleanKey, defaultLoadDataClean)
	viper.BindEnv(loadDataCleanKey, "SFTPGO_LOADDATA_CLEAN") //nolint:errcheck
	cmd.Flags().BoolVar(&loadDataClean, loadDataCleanFlag, viper.GetBool(loadDataCleanKey),
		`Determine if the loaddata-from file should
be removed after a successful load. This flag
can be set using SFTPGO_LOADDATA_CLEAN env var
too. (default "false")
`)
	viper.BindPFlag(loadDataCleanKey, cmd.Flags().Lookup(loadDataCleanFlag)) //nolint:errcheck
}

func addServeFlags(cmd *cobra.Command) {
	addConfigFlags(cmd)

	viper.SetDefault(logFilePathKey, defaultLogFile)
	viper.BindEnv(logFilePathKey, "SFTPGO_LOG_FILE_PATH") //nolint:errcheck
	cmd.Flags().StringVarP(&logFilePath, logFilePathFlag, "l", viper.GetString(logFilePathKey),
		`Location for the log file. Leave empty to write
logs to the standard output. This flag can be
set using SFTPGO_LOG_FILE_PATH env var too.
`)
	viper.BindPFlag(logFilePathKey, cmd.Flags().Lookup(logFilePathFlag)) //nolint:errcheck

	viper.SetDefault(logMaxSizeKey, defaultLogMaxSize)
	viper.BindEnv(logMaxSizeKey, "SFTPGO_LOG_MAX_SIZE") //nolint:errcheck
	cmd.Flags().IntVarP(&logMaxSize, logMaxSizeFlag, "s", viper.GetInt(logMaxSizeKey),
		`Maximum size in megabytes of the log file
before it gets rotated. This flag can be set
using SFTPGO_LOG_MAX_SIZE env var too. It is
unused if log-file-path is empty.
`)
	viper.BindPFlag(logMaxSizeKey, cmd.Flags().Lookup(logMaxSizeFlag)) //nolint:errcheck

	viper.SetDefault(logMaxBackupKey, defaultLogMaxBackup)
	viper.BindEnv(logMaxBackupKey, "SFTPGO_LOG_MAX_BACKUPS") //nolint:errcheck
	cmd.Flags().IntVarP(&logMaxBackups, "log-max-backups", "b", viper.GetInt(logMaxBackupKey),
		`Maximum number of old log files to retain.
This flag can be set using SFTPGO_LOG_MAX_BACKUPS
env var too. It is unused if log-file-path is
empty.`)
	viper.BindPFlag(logMaxBackupKey, cmd.Flags().Lookup(logMaxBackupFlag)) //nolint:errcheck

	viper.SetDefault(logMaxAgeKey, defaultLogMaxAge)
	viper.BindEnv(logMaxAgeKey, "SFTPGO_LOG_MAX_AGE") //nolint:errcheck
	cmd.Flags().IntVarP(&logMaxAge, "log-max-age", "a", viper.GetInt(logMaxAgeKey),
		`Maximum number of days to retain old log files.
This flag can be set using SFTPGO_LOG_MAX_AGE env
var too. It is unused if log-file-path is empty.
`)
	viper.BindPFlag(logMaxAgeKey, cmd.Flags().Lookup(logMaxAgeFlag)) //nolint:errcheck

	viper.SetDefault(logCompressKey, defaultLogCompress)
	viper.BindEnv(logCompressKey, "SFTPGO_LOG_COMPRESS") //nolint:errcheck
	cmd.Flags().BoolVarP(&logCompress, logCompressFlag, "z", viper.GetBool(logCompressKey),
		`Determine if the rotated log files
should be compressed using gzip. This flag can
be set using SFTPGO_LOG_COMPRESS env var too.
It is unused if log-file-path is empty.
`)
	viper.BindPFlag(logCompressKey, cmd.Flags().Lookup(logCompressFlag)) //nolint:errcheck

	viper.SetDefault(logVerboseKey, defaultLogVerbose)
	viper.BindEnv(logVerboseKey, "SFTPGO_LOG_VERBOSE") //nolint:errcheck
	cmd.Flags().BoolVarP(&logVerbose, logVerboseFlag, "v", viper.GetBool(logVerboseKey),
		`Enable verbose logs. This flag can be set
using SFTPGO_LOG_VERBOSE env var too.
`)
	viper.BindPFlag(logVerboseKey, cmd.Flags().Lookup(logVerboseFlag)) //nolint:errcheck

	viper.SetDefault(logUTCTimeKey, defaultLogUTCTime)
	viper.BindEnv(logUTCTimeKey, "SFTPGO_LOG_UTC_TIME") //nolint:errcheck
	cmd.Flags().BoolVar(&logUTCTime, logUTCTimeFlag, viper.GetBool(logUTCTimeKey),
		`Use UTC time for logging. This flag can be set
using SFTPGO_LOG_UTC_TIME env var too.
`)
	viper.BindPFlag(logUTCTimeKey, cmd.Flags().Lookup(logUTCTimeFlag)) //nolint:errcheck

	addBaseLoadDataFlags(cmd)

	viper.SetDefault(loadDataQuotaScanKey, defaultLoadDataQuotaScan)
	viper.BindEnv(loadDataQuotaScanKey, "SFTPGO_LOADDATA_QUOTA_SCAN") //nolint:errcheck
	cmd.Flags().IntVar(&loadDataQuotaScan, loadDataQuotaScanFlag, viper.GetInt(loadDataQuotaScanKey),
		`Quota scan mode after data load:
  0 - no quota scan
  1 - scan quota
  2 - scan quota if the user has quota restrictions
This flag can be set using SFTPGO_LOADDATA_QUOTA_SCAN
env var too.
(default 0)`)
	viper.BindPFlag(loadDataQuotaScanKey, cmd.Flags().Lookup(loadDataQuotaScanFlag)) //nolint:errcheck
}
