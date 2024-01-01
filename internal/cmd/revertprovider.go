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

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	revertProviderTargetVersion int
	revertProviderCmd           = &cobra.Command{
		Use:   "revertprovider",
		Short: "Revert the configured data provider to a previous version",
		Long: `This command reads the data provider connection details from the specified
configuration file and restore the provider schema and/or data to a previous version.
This command is not supported for the memory provider.

Please take a look at the usage below to customize the options.`,
		Run: func(_ *cobra.Command, _ []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			if revertProviderTargetVersion != 28 {
				logger.WarnToConsole("Unsupported target version, 28 is the only supported one")
				os.Exit(1)
			}
			configDir = util.CleanDirInput(configDir)
			err := config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.WarnToConsole("Unable to load configuration: %v", err)
				os.Exit(1)
			}
			kmsConfig := config.GetKMSConfig()
			err = kmsConfig.Initialize()
			if err != nil {
				logger.ErrorToConsole("unable to initialize KMS: %v", err)
				os.Exit(1)
			}
			providerConf := config.GetProviderConf()
			logger.InfoToConsole("Reverting provider: %q config file: %q target version %d", providerConf.Driver,
				viper.ConfigFileUsed(), revertProviderTargetVersion)
			err = dataprovider.RevertDatabase(providerConf, configDir, revertProviderTargetVersion)
			if err != nil {
				logger.WarnToConsole("Error reverting provider: %v", err)
				os.Exit(1)
			}
			logger.InfoToConsole("Data provider successfully reverted")
		},
	}
)

func init() {
	addConfigFlags(revertProviderCmd)
	revertProviderCmd.Flags().IntVar(&revertProviderTargetVersion, "to-version", 28, `28 means the version supported in v2.5.x`)

	rootCmd.AddCommand(revertProviderCmd)
}
