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
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/internal/service"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	installCmd = &cobra.Command{
		Use:   "install",
		Short: "Install SFTPGo as Windows Service",
		Long: `To install the SFTPGo Windows Service with the default values for the command
line flags simply use:

sftpgo service install

Please take a look at the usage below to customize the startup options`,
		Run: func(_ *cobra.Command, _ []string) {
			s := service.Service{
				ConfigDir:     util.CleanDirInput(configDir),
				ConfigFile:    configFile,
				LogFilePath:   logFilePath,
				LogMaxSize:    logMaxSize,
				LogMaxBackups: logMaxBackups,
				LogMaxAge:     logMaxAge,
				LogCompress:   logCompress,
				LogLevel:      logLevel,
				LogUTCTime:    logUTCTime,
				Shutdown:      make(chan bool),
			}
			winService := service.WindowsService{
				Service: s,
			}
			serviceArgs := []string{"service", "start"}
			customFlags := getCustomServeFlags()
			if len(customFlags) > 0 {
				serviceArgs = append(serviceArgs, customFlags...)
			}
			err := winService.Install(serviceArgs...)
			if err != nil {
				fmt.Printf("Error installing service: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Service installed!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(installCmd)
	addServeFlags(installCmd)
}

func getCustomServeFlags() []string {
	result := []string{}
	if configDir != defaultConfigDir {
		configDir = util.CleanDirInput(configDir)
		result = append(result, "--"+configDirFlag)
		result = append(result, configDir)
	}
	if configFile != defaultConfigFile {
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
	if logLevel != defaultLogLevel {
		result = append(result, "--"+logLevelFlag)
		result = append(result, logLevel)
	}
	if logUTCTime != defaultLogUTCTime {
		result = append(result, "--"+logUTCTimeFlag+"=true")
	}
	if logCompress != defaultLogCompress {
		result = append(result, "--"+logCompressFlag+"=true")
	}
	if graceTime != defaultGraceTime {
		result = append(result, "--"+graceTimeFlag)
		result = append(result, strconv.Itoa(graceTime))
	}
	return result
}
