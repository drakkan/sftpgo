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

	"github.com/drakkan/sftpgo/v2/internal/acme"
	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
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
		Run: func(_ *cobra.Command, _ []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			configDir = util.CleanDirInput(configDir)
			err := config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.ErrorToConsole("Unable to initialize ACME, config load error: %v", err)
				return
			}
			kmsConfig := config.GetKMSConfig()
			err = kmsConfig.Initialize()
			if err != nil {
				logger.ErrorToConsole("unable to initialize KMS: %v", err)
				os.Exit(1)
			}
			mfaConfig := config.GetMFAConfig()
			err = mfaConfig.Initialize()
			if err != nil {
				logger.ErrorToConsole("Unable to initialize MFA: %v", err)
				os.Exit(1)
			}
			providerConf := config.GetProviderConf()
			err = dataprovider.Initialize(providerConf, configDir, false)
			if err != nil {
				logger.ErrorToConsole("error initializing data provider: %v", err)
				os.Exit(1)
			}
			acmeConfig := config.GetACMEConfig()
			err = acme.Initialize(acmeConfig, configDir, false)
			if err != nil {
				logger.ErrorToConsole("Unable to initialize ACME configuration: %v", err)
				os.Exit(1)
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
