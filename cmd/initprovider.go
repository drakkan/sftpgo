package cmd

import (
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	initProviderCmd = &cobra.Command{
		Use:   "initprovider",
		Short: "Initializes the configured data provider",
		Long: `This command reads the data provider connection details from the specified configuration file and creates the initial structure.

Some data providers such as bolt and memory does not require an initialization.

For SQLite provider the database file will be auto created if missing.

For PostgreSQL and MySQL providers you need to create the configured database, this command will create the required tables.

To initialize the data provider from the configuration directory simply use:

sftpgo initprovider

Please take a look at the usage below to customize the options.`,
		Run: func(cmd *cobra.Command, args []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			configDir = utils.CleanDirInput(configDir)
			config.LoadConfig(configDir, configFile)
			providerConf := config.GetProviderConf()
			logger.DebugToConsole("Initializing provider: %#v config file: %#v", providerConf.Driver, viper.ConfigFileUsed())
			err := dataprovider.InitializeDatabase(providerConf, configDir)
			if err == nil {
				logger.DebugToConsole("Data provider successfully initialized")
			} else {
				logger.WarnToConsole("Unable to initialize data provider: %v", err)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(initProviderCmd)
	addConfigFlags(initProviderCmd)
}
