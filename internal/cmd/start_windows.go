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

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/internal/service"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	startCmd = &cobra.Command{
		Use:   "start",
		Short: "Start the SFTPGo Windows Service",
		Run: func(_ *cobra.Command, _ []string) {
			configDir = util.CleanDirInput(configDir)
			checkServeParamsFromEnvFiles(configDir)
			service.SetGraceTime(graceTime)
			s := service.Service{
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
			winService := service.WindowsService{
				Service: s,
			}
			err := winService.RunService()
			if err != nil {
				fmt.Printf("Error starting service: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Service started!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(startCmd)
	addServeFlags(startCmd)
}
