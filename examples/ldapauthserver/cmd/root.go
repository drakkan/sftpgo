package cmd

import (
	"fmt"
	"os"

	"github.com/drakkan/sftpgo/ldapauthserver/config"
	"github.com/drakkan/sftpgo/ldapauthserver/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	logSender           = "cmd"
	configDirFlag       = "config-dir"
	configDirKey        = "config_dir"
	configFileFlag      = "config-file"
	configFileKey       = "config_file"
	logFilePathFlag     = "log-file-path"
	logFilePathKey      = "log_file_path"
	logMaxSizeFlag      = "log-max-size"
	logMaxSizeKey       = "log_max_size"
	logMaxBackupFlag    = "log-max-backups"
	logMaxBackupKey     = "log_max_backups"
	logMaxAgeFlag       = "log-max-age"
	logMaxAgeKey        = "log_max_age"
	logCompressFlag     = "log-compress"
	logCompressKey      = "log_compress"
	logVerboseFlag      = "log-verbose"
	logVerboseKey       = "log_verbose"
	profilerFlag        = "profiler"
	profilerKey         = "profiler"
	defaultConfigDir    = "."
	defaultConfigName   = config.DefaultConfigName
	defaultLogFile      = "ldapauth.log"
	defaultLogMaxSize   = 10
	defaultLogMaxBackup = 5
	defaultLogMaxAge    = 28
	defaultLogCompress  = false
	defaultLogVerbose   = true
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

	rootCmd = &cobra.Command{
		Use:   "ldapauthserver",
		Short: "LDAP Authentication Server for SFTPGo",
	}
)

func init() {
	version := utils.GetAppVersion()
	rootCmd.Flags().BoolP("version", "v", false, "")
	rootCmd.Version = version.GetVersionAsString()
	rootCmd.SetVersionTemplate(`{{printf "LDAP Authentication Server version: "}}{{printf "%s" .Version}}
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
	viper.BindEnv(configDirKey, "LDAPAUTH_CONFIG_DIR")
	cmd.Flags().StringVarP(&configDir, configDirFlag, "c", viper.GetString(configDirKey),
		`Location for the config dir. This directory
should contain the "ldapauth" configuration
file or the configured config-file. This flag
can be set using LDAPAUTH_CONFIG_DIR env var too.
`)
	viper.BindPFlag(configDirKey, cmd.Flags().Lookup(configDirFlag))

	viper.SetDefault(configFileKey, defaultConfigName)
	viper.BindEnv(configFileKey, "LDAPAUTH_CONFIG_FILE")
	cmd.Flags().StringVarP(&configFile, configFileFlag, "f", viper.GetString(configFileKey),
		`Name for the configuration file. It must be
the name of a file stored in config-dir not
the absolute path to the configuration file.
The specified file name must have no extension
we automatically load JSON, YAML, TOML, HCL and
Java properties. Therefore if you set \"ldapauth\"
then \"ldapauth.toml\", \"ldapauth.yaml\" and
so on are searched. This flag can be set using
LDAPAUTH_CONFIG_FILE env var too.
`)
	viper.BindPFlag(configFileKey, cmd.Flags().Lookup(configFileFlag))
}

func addServeFlags(cmd *cobra.Command) {
	addConfigFlags(cmd)

	viper.SetDefault(logFilePathKey, defaultLogFile)
	viper.BindEnv(logFilePathKey, "LDAPAUTH_LOG_FILE_PATH")
	cmd.Flags().StringVarP(&logFilePath, logFilePathFlag, "l", viper.GetString(logFilePathKey),
		`Location for the log file. Leave empty to write
logs to the standard output. This flag can be
set using LDAPAUTH_LOG_FILE_PATH env var too.
`)
	viper.BindPFlag(logFilePathKey, cmd.Flags().Lookup(logFilePathFlag))

	viper.SetDefault(logMaxSizeKey, defaultLogMaxSize)
	viper.BindEnv(logMaxSizeKey, "LDAPAUTH_LOG_MAX_SIZE")
	cmd.Flags().IntVarP(&logMaxSize, logMaxSizeFlag, "s", viper.GetInt(logMaxSizeKey),
		`Maximum size in megabytes of the log file
before it gets rotated. This flag can be set
using LDAPAUTH_LOG_MAX_SIZE env var too. It
is unused if log-file-path is empty.`)
	viper.BindPFlag(logMaxSizeKey, cmd.Flags().Lookup(logMaxSizeFlag))

	viper.SetDefault(logMaxBackupKey, defaultLogMaxBackup)
	viper.BindEnv(logMaxBackupKey, "LDAPAUTH_LOG_MAX_BACKUPS")
	cmd.Flags().IntVarP(&logMaxBackups, "log-max-backups", "b", viper.GetInt(logMaxBackupKey),
		`Maximum number of old log files to retain.
This flag can be set using LDAPAUTH_LOG_MAX_BACKUPS
env var too. It is unused if log-file-path is
empty.`)
	viper.BindPFlag(logMaxBackupKey, cmd.Flags().Lookup(logMaxBackupFlag))

	viper.SetDefault(logMaxAgeKey, defaultLogMaxAge)
	viper.BindEnv(logMaxAgeKey, "LDAPAUTH_LOG_MAX_AGE")
	cmd.Flags().IntVarP(&logMaxAge, "log-max-age", "a", viper.GetInt(logMaxAgeKey),
		`Maximum number of days to retain old log files.
This flag can be set using LDAPAUTH_LOG_MAX_AGE
env var too. It is unused if log-file-path is
empty.`)
	viper.BindPFlag(logMaxAgeKey, cmd.Flags().Lookup(logMaxAgeFlag))

	viper.SetDefault(logCompressKey, defaultLogCompress)
	viper.BindEnv(logCompressKey, "LDAPAUTH_LOG_COMPRESS")
	cmd.Flags().BoolVarP(&logCompress, logCompressFlag, "z", viper.GetBool(logCompressKey),
		`Determine if the rotated log files
should be compressed using gzip. This flag can
be set using LDAPAUTH_LOG_COMPRESS env var too.
It is unused if log-file-path is empty.`)
	viper.BindPFlag(logCompressKey, cmd.Flags().Lookup(logCompressFlag))

	viper.SetDefault(logVerboseKey, defaultLogVerbose)
	viper.BindEnv(logVerboseKey, "LDAPAUTH_LOG_VERBOSE")
	cmd.Flags().BoolVarP(&logVerbose, logVerboseFlag, "v", viper.GetBool(logVerboseKey),
		`Enable verbose logs. This flag can be set
using LDAPAUTH_LOG_VERBOSE env var too.
`)
	viper.BindPFlag(logVerboseKey, cmd.Flags().Lookup(logVerboseFlag))
}
