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
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/service"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	initProviderCmd = &cobra.Command{
		Use:   "initprovider",
		Short: "Initialize and/or updates the configured data provider",
		Long: `This command reads the data provider connection details from the specified
configuration file and creates the initial structure or update the existing one,
as needed.

Some data providers such as bolt and memory does not require an initialization
but they could require an update to the existing data after upgrading SFTPGo.

For SQLite/bolt providers the database file will be auto-created if missing.

For PostgreSQL and MySQL providers you need to create the configured database,
this command will create/update the required tables as needed.

To initialize/update the data provider from the configuration directory simply use:

$ sftpgo initprovider

Any defined action is ignored.
Please take a look at the usage below to customize the options.`,
		Run: func(_ *cobra.Command, _ []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			configDir = util.CleanDirInput(configDir)
			err := config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.ErrorToConsole("Unable to initialize data provider, config load error: %v", err)
				return
			}
			kmsConfig := config.GetKMSConfig()
			err = kmsConfig.Initialize()
			if err != nil {
				logger.ErrorToConsole("Unable to initialize KMS: %v", err)
				os.Exit(1)
			}
			if config.HasKMSPlugin() {
				if err := plugin.Initialize(config.GetPluginsConfig(), "debug"); err != nil {
					logger.ErrorToConsole("unable to initialize plugin system: %v", err)
					os.Exit(1)
				}
				registerSignals()
				defer plugin.Handler.Cleanup()
			}

			mfaConfig := config.GetMFAConfig()
			err = mfaConfig.Initialize()
			if err != nil {
				logger.ErrorToConsole("Unable to initialize MFA: %v", err)
				os.Exit(1)
			}
			providerConf := config.GetProviderConf()
			// ignore actions
			providerConf.Actions.Hook = ""
			providerConf.Actions.ExecuteFor = nil
			providerConf.Actions.ExecuteOn = nil
			logger.InfoToConsole("Initializing provider: %q config file: %q", providerConf.Driver, viper.ConfigFileUsed())
			err = dataprovider.InitializeDatabase(providerConf, configDir)
			switch err {
			case nil:
				logger.InfoToConsole("Data provider successfully initialized/updated")
			case dataprovider.ErrNoInitRequired:
				logger.InfoToConsole("%v", err.Error())
			default:
				logger.ErrorToConsole("Unable to initialize/update the data provider: %v", err)
				os.Exit(1)
			}
			if providerConf.Driver != dataprovider.MemoryDataProviderName && loadDataFrom != "" {
				service := service.Service{
					LoadDataFrom:      loadDataFrom,
					LoadDataMode:      loadDataMode,
					LoadDataQuotaScan: loadDataQuotaScan,
					LoadDataClean:     loadDataClean,
				}
				if err = service.LoadInitialData(); err != nil {
					logger.ErrorToConsole("Cannot load initial data: %v", err)
					os.Exit(1)
				}
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(initProviderCmd)
	addConfigFlags(initProviderCmd)
	addBaseLoadDataFlags(initProviderCmd)
}
