package cmd

import (
	"bufio"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

var (
	resetProviderForce bool
	resetProviderCmd   = &cobra.Command{
		Use:   "resetprovider",
		Short: "Reset the configured provider, any data will be lost",
		Long: `This command reads the data provider connection details from the specified
configuration file and resets the provider by deleting all data and schemas.
This command is not supported for the memory provider.

Please take a look at the usage below to customize the options.`,
		Run: func(cmd *cobra.Command, args []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
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
			if !resetProviderForce {
				logger.WarnToConsole("You are about to delete all the SFTPGo data for provider %#v, config file: %#v",
					providerConf.Driver, viper.ConfigFileUsed())
				logger.WarnToConsole("Are you sure? (Y/n)")
				reader := bufio.NewReader(os.Stdin)
				answer, err := reader.ReadString('\n')
				if err != nil {
					logger.ErrorToConsole("unable to read your answer: %v", err)
					os.Exit(1)
				}
				if strings.ToUpper(strings.TrimSpace(answer)) != "Y" {
					logger.InfoToConsole("command aborted")
					os.Exit(1)
				}
			}
			logger.InfoToConsole("Resetting provider: %#v, config file: %#v", providerConf.Driver, viper.ConfigFileUsed())
			err = dataprovider.ResetDatabase(providerConf, configDir)
			if err != nil {
				logger.WarnToConsole("Error resetting provider: %v", err)
				os.Exit(1)
			}
			logger.InfoToConsole("Tha data provider was successfully reset")
		},
	}
)

func init() {
	addConfigFlags(resetProviderCmd)
	resetProviderCmd.Flags().BoolVar(&resetProviderForce, "force", false, `reset the provider without asking for confirmation`)

	rootCmd.AddCommand(resetProviderCmd)
}
