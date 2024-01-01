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

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/internal/service"
	"github.com/drakkan/sftpgo/v2/internal/util"
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
			service.SetGraceTime(graceTime)
			service := service.Service{
				ConfigDir:         util.CleanDirInput(configDir),
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

func init() {
	rootCmd.AddCommand(serveCmd)
	addServeFlags(serveCmd)
	addAWSContainerFlags(serveCmd)
}
