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
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/subosito/gotenv"

	"github.com/drakkan/sftpgo/v2/internal/service"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	envFileMaxSize = 1048576
)

var (
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the SFTPGo service",
		Long: `To start the SFTPGo with the default values for the command line flags simply
use:

$ sftpgo serve

Please take a look at the usage below to customize the startup options`,
		Run: func(_ *cobra.Command, _ []string) {
			configDir := util.CleanDirInput(configDir)
			checkServeParamsFromEnvFiles(configDir)
			service.SetGraceTime(graceTime)
			service := service.Service{
				ConfigDir:         configDir,
				ConfigFile:        configFile,
				LogFilePath:       logFilePath,
				LogMaxSize:        logMaxSize,
				LogMaxBackups:     logMaxBackups,
				LogMaxAge:         logMaxAge,
				LogCompress:       logCompress,
				LogLevel:          logLevel,
				LogUTCTime:        logUTCTime,
				LoadDataFrom:      loadDataFrom,
				LoadDataMode:      loadDataMode,
				LoadDataQuotaScan: loadDataQuotaScan,
				LoadDataClean:     loadDataClean,
				Shutdown:          make(chan bool),
			}
			if err := service.Start(disableAWSInstallationCode); err == nil {
				service.Wait()
				if service.Error == nil {
					os.Exit(0)
				}
			}
			os.Exit(1)
		},
	}
)

func setIntFromEnv(receiver *int, val string) {
	converted, err := strconv.Atoi(val)
	if err == nil {
		*receiver = converted
	}
}

func setBoolFromEnv(receiver *bool, val string) {
	converted, err := strconv.ParseBool(strings.TrimSpace(val))
	if err == nil {
		*receiver = converted
	}
}

func checkServeParamsFromEnvFiles(configDir string) { //nolint:gocyclo
	// The logger is not yet initialized here, we have no way to report errors.
	envd := filepath.Join(configDir, "env.d")
	entries, err := os.ReadDir(envd)
	if err != nil {
		return
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err == nil && info.Mode().IsRegular() {
			envFile := filepath.Join(envd, entry.Name())
			if info.Size() > envFileMaxSize {
				continue
			}
			envVars, err := gotenv.Read(envFile)
			if err != nil {
				return
			}
			for k, v := range envVars {
				if _, isSet := os.LookupEnv(k); isSet {
					continue
				}
				switch k {
				case "SFTPGO_LOG_FILE_PATH":
					logFilePath = v
				case "SFTPGO_LOG_MAX_SIZE":
					setIntFromEnv(&logMaxSize, v)
				case "SFTPGO_LOG_MAX_BACKUPS":
					setIntFromEnv(&logMaxBackups, v)
				case "SFTPGO_LOG_MAX_AGE":
					setIntFromEnv(&logMaxAge, v)
				case "SFTPGO_LOG_COMPRESS":
					setBoolFromEnv(&logCompress, v)
				case "SFTPGO_LOG_LEVEL":
					logLevel = v
				case "SFTPGO_LOG_UTC_TIME":
					setBoolFromEnv(&logUTCTime, v)
				case "SFTPGO_CONFIG_FILE":
					configFile = v
				case "SFTPGO_LOADDATA_FROM":
					loadDataFrom = v
				case "SFTPGO_LOADDATA_MODE":
					setIntFromEnv(&loadDataMode, v)
				case "SFTPGO_LOADDATA_CLEAN":
					setBoolFromEnv(&loadDataClean, v)
				case "SFTPGO_LOADDATA_QUOTA_SCAN":
					setIntFromEnv(&loadDataQuotaScan, v)
				case "SFTPGO_GRACE_TIME":
					setIntFromEnv(&graceTime, v)
				}
			}
		}
	}
}

func init() {
	rootCmd.AddCommand(serveCmd)
	addServeFlags(serveCmd)
	addAWSContainerFlags(serveCmd)
}
