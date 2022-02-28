package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/service"
	"github.com/drakkan/sftpgo/v2/util"
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

Please take a look at the usage below to customize the options.`,
		Run: func(cmd *cobra.Command, args []string) {
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
			providerConf := config.GetProviderConf()
			logger.InfoToConsole("Initializing provider: %#v config file: %#v", providerConf.Driver, viper.ConfigFileUsed())
			err = dataprovider.InitializeDatabase(providerConf, configDir)
			if err == nil {
				logger.InfoToConsole("Data provider successfully initialized/updated")
			} else if err == dataprovider.ErrNoInitRequired {
				logger.InfoToConsole("%v", err.Error())
			} else {
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
