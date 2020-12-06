package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
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
		Run: func(cmd *cobra.Command, args []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			configDir = utils.CleanDirInput(configDir)
			err := config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.WarnToConsole("Unable to initialize data provider, config load error: %v", err)
				return
			}
			kmsConfig := config.GetKMSConfig()
			err = kmsConfig.Initialize()
			if err != nil {
				logger.ErrorToConsole("unable to initialize KMS: %v", err)
				os.Exit(1)
			}
			providerConf := config.GetProviderConf()
			logger.InfoToConsole("Reverting provider: %#v config file: %#v target version %v", providerConf.Driver,
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
	revertProviderCmd.Flags().IntVar(&revertProviderTargetVersion, "to-version", 0, `4 means the version supported in v1.0.0-v1.2.x`)

	rootCmd.AddCommand(revertProviderCmd)
}
