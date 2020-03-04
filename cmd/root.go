// Package cmd provides Command Line Interface support
package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/utils"
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
	defaultConfigDir    = "."
	defaultConfigName   = config.DefaultConfigName
	defaultLogFile      = "sftpgo.log"
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
		Use:   "sftpgo",
		Short: "Full featured and highly configurable SFTP server",
	}
)

func init() {
	version := utils.GetAppVersion()
	rootCmd.Flags().BoolP("version", "v", false, "")
	rootCmd.Version = version.GetVersionAsString()
	rootCmd.SetVersionTemplate(`{{printf "SFTPGo version: "}}{{printf "%s" .Version}}
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
	viper.BindEnv(configDirKey, "SFTPGO_CONFIG_DIR")
	cmd.Flags().StringVarP(&configDir, configDirFlag, "c", viper.GetString(configDirKey),
		"Location for SFTPGo config dir. This directory should contain the \"sftpgo\" configuration file or the configured "+
			"config-file and it is used as the base for files with a relative path (eg. the private keys for the SFTP server, "+
			"the SQLite database if you use SQLite as data provider). This flag can be set using SFTPGO_CONFIG_DIR env var too.")
	viper.BindPFlag(configDirKey, cmd.Flags().Lookup(configDirFlag))

	viper.SetDefault(configFileKey, defaultConfigName)
	viper.BindEnv(configFileKey, "SFTPGO_CONFIG_FILE")
	cmd.Flags().StringVarP(&configFile, configFileFlag, "f", viper.GetString(configFileKey),
		"Name for SFTPGo configuration file. It must be the name of a file stored in config-dir not the absolute path to the "+
			"configuration file. The specified file name must have no extension we automatically load JSON, YAML, TOML, HCL and "+
			"Java properties. Therefore if you set \"sftpgo\" then \"sftpgo.json\", \"sftpgo.yaml\" and so on are searched. "+
			"This flag can be set using SFTPGO_CONFIG_FILE env var too.")
	viper.BindPFlag(configFileKey, cmd.Flags().Lookup(configFileFlag))
}

func addServeFlags(cmd *cobra.Command) {
	addConfigFlags(cmd)

	viper.SetDefault(logFilePathKey, defaultLogFile)
	viper.BindEnv(logFilePathKey, "SFTPGO_LOG_FILE_PATH")
	cmd.Flags().StringVarP(&logFilePath, logFilePathFlag, "l", viper.GetString(logFilePathKey),
		"Location for the log file. Leave empty to write logs to the standard output. This flag can be set using SFTPGO_LOG_FILE_PATH "+
			"env var too.")
	viper.BindPFlag(logFilePathKey, cmd.Flags().Lookup(logFilePathFlag))

	viper.SetDefault(logMaxSizeKey, defaultLogMaxSize)
	viper.BindEnv(logMaxSizeKey, "SFTPGO_LOG_MAX_SIZE")
	cmd.Flags().IntVarP(&logMaxSize, logMaxSizeFlag, "s", viper.GetInt(logMaxSizeKey),
		"Maximum size in megabytes of the log file before it gets rotated. This flag can be set using SFTPGO_LOG_MAX_SIZE "+
			"env var too. It is unused if log-file-path is empty.")
	viper.BindPFlag(logMaxSizeKey, cmd.Flags().Lookup(logMaxSizeFlag))

	viper.SetDefault(logMaxBackupKey, defaultLogMaxBackup)
	viper.BindEnv(logMaxBackupKey, "SFTPGO_LOG_MAX_BACKUPS")
	cmd.Flags().IntVarP(&logMaxBackups, "log-max-backups", "b", viper.GetInt(logMaxBackupKey),
		"Maximum number of old log files to retain. This flag can be set using SFTPGO_LOG_MAX_BACKUPS env var too. "+
			"It is unused if log-file-path is empty.")
	viper.BindPFlag(logMaxBackupKey, cmd.Flags().Lookup(logMaxBackupFlag))

	viper.SetDefault(logMaxAgeKey, defaultLogMaxAge)
	viper.BindEnv(logMaxAgeKey, "SFTPGO_LOG_MAX_AGE")
	cmd.Flags().IntVarP(&logMaxAge, "log-max-age", "a", viper.GetInt(logMaxAgeKey),
		"Maximum number of days to retain old log files. This flag can be set using SFTPGO_LOG_MAX_AGE env var too. "+
			"It is unused if log-file-path is empty.")
	viper.BindPFlag(logMaxAgeKey, cmd.Flags().Lookup(logMaxAgeFlag))

	viper.SetDefault(logCompressKey, defaultLogCompress)
	viper.BindEnv(logCompressKey, "SFTPGO_LOG_COMPRESS")
	cmd.Flags().BoolVarP(&logCompress, logCompressFlag, "z", viper.GetBool(logCompressKey), "Determine if the rotated "+
		"log files should be compressed using gzip. This flag can be set using SFTPGO_LOG_COMPRESS env var too. "+
		"It is unused if log-file-path is empty.")
	viper.BindPFlag(logCompressKey, cmd.Flags().Lookup(logCompressFlag))

	viper.SetDefault(logVerboseKey, defaultLogVerbose)
	viper.BindEnv(logVerboseKey, "SFTPGO_LOG_VERBOSE")
	cmd.Flags().BoolVarP(&logVerbose, logVerboseFlag, "v", viper.GetBool(logVerboseKey), "Enable verbose logs. "+
		"This flag can be set using SFTPGO_LOG_VERBOSE env var too.")
	viper.BindPFlag(logVerboseKey, cmd.Flags().Lookup(logVerboseFlag))
}

func getCustomServeFlags() []string {
	result := []string{}
	if configDir != defaultConfigDir {
		configDir = utils.CleanDirInput(configDir)
		result = append(result, "--"+configDirFlag)
		result = append(result, configDir)
	}
	if configFile != defaultConfigName {
		result = append(result, "--"+configFileFlag)
		result = append(result, configFile)
	}
	if logFilePath != defaultLogFile {
		result = append(result, "--"+logFilePathFlag)
		result = append(result, logFilePath)
	}
	if logMaxSize != defaultLogMaxSize {
		result = append(result, "--"+logMaxSizeFlag)
		result = append(result, strconv.Itoa(logMaxSize))
	}
	if logMaxBackups != defaultLogMaxBackup {
		result = append(result, "--"+logMaxBackupFlag)
		result = append(result, strconv.Itoa(logMaxBackups))
	}
	if logMaxAge != defaultLogMaxAge {
		result = append(result, "--"+logMaxAgeFlag)
		result = append(result, strconv.Itoa(logMaxAge))
	}
	if logVerbose != defaultLogVerbose {
		result = append(result, "--"+logVerboseFlag+"=false")
	}
	if logCompress != defaultLogCompress {
		result = append(result, "--"+logCompressFlag+"=true")
	}
	return result
}
