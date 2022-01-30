package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
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
			if revertProviderTargetVersion != 15 {
				logger.WarnToConsole("Unsupported target version, 15 is the only supported one")
				os.Exit(1)
			}
			configDir = util.CleanDirInput(configDir)
			err := config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.WarnToConsole("Unable to initialize data provider, config load error: %v", err)
				os.Exit(1)
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
	revertProviderCmd.Flags().IntVar(&revertProviderTargetVersion, "to-version", 15, `15 means the version supported in v2.2.x`)
	revertProviderCmd.MarkFlagRequired("to-version") //nolint:errcheck

	rootCmd.AddCommand(revertProviderCmd)
}
