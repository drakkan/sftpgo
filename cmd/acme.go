package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/acme"
	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

var (
	acmeCmd = &cobra.Command{
		Use:   "acme",
		Short: "Obtain TLS certificates from ACME-based CAs like Let's Encrypt",
	}
	acmeRunCmd = &cobra.Command{
		Use:   "run",
		Short: "Register your account and obtain certificates",
		Long: `This command must be run to obtain TLS certificates the first time or every
time you add a new domain to your configuration file.
Certificates are saved in the configured "certs_path".
After this initial step, the certificates are automatically checked and
renewed by the SFTPGo service
`,
		Run: func(cmd *cobra.Command, args []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			configDir = util.CleanDirInput(configDir)
			err := config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.ErrorToConsole("Unable to initialize data provider, config load error: %v", err)
				return
			}
			acmeConfig := config.GetACMEConfig()
			err = acmeConfig.Initialize(configDir, false)
			if err != nil {
				logger.ErrorToConsole("Unable to initialize ACME configuration: %v", err)
			}
			if err = acme.GetCertificates(); err != nil {
				logger.ErrorToConsole("Cannot get certificates: %v", err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	addConfigFlags(acmeRunCmd)
	acmeCmd.AddCommand(acmeRunCmd)
	rootCmd.AddCommand(acmeCmd)
}
