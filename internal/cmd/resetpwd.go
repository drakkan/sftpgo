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
	"bytes"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	resetPwdAdmin string
	resetPwdCmd   = &cobra.Command{
		Use:   "resetpwd",
		Short: "Reset the password for the specified administrator",
		Long: `This command reads the data provider connection details from the specified
configuration file and resets the password for the specified administrator.
This command is not supported for the memory provider.
For embedded providers like bolt and SQLite you should stop the running SFTPGo
instance to avoid database corruption.

Please take a look at the usage below to customize the options.`,
		Run: func(_ *cobra.Command, _ []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
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
			mfaConfig := config.GetMFAConfig()
			err = mfaConfig.Initialize()
			if err != nil {
				logger.ErrorToConsole("Unable to initialize MFA: %v", err)
				os.Exit(1)
			}
			providerConf := config.GetProviderConf()
			if providerConf.Driver == dataprovider.MemoryDataProviderName {
				logger.ErrorToConsole("memory provider is not supported")
				os.Exit(1)
			}
			logger.InfoToConsole("Initializing provider: %q config file: %q", providerConf.Driver, viper.ConfigFileUsed())
			err = dataprovider.Initialize(providerConf, configDir, false)
			if err != nil {
				logger.ErrorToConsole("Unable to initialize data provider: %v", err)
				os.Exit(1)
			}
			admin, err := dataprovider.AdminExists(resetPwdAdmin)
			if err != nil {
				logger.ErrorToConsole("Unable to get admin %q: %v", resetPwdAdmin, err)
				os.Exit(1)
			}
			fmt.Printf("Enter Password: ")
			pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				logger.ErrorToConsole("Unable to read the password: %v", err)
				os.Exit(1)
			}
			fmt.Println("")
			fmt.Printf("Confirm Password: ")
			confirmPwd, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				logger.ErrorToConsole("Unable to read the password: %v", err)
				os.Exit(1)
			}
			fmt.Println("")
			if !bytes.Equal(pwd, confirmPwd) {
				logger.ErrorToConsole("Passwords do not match")
				os.Exit(1)
			}
			admin.Password = string(pwd)
			if err := dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSystem, "", ""); err != nil {
				logger.ErrorToConsole("Unable to update password: %v", err)
				os.Exit(1)
			}
			logger.InfoToConsole("Password updated for admin %q", resetPwdAdmin)
		},
	}
)

func init() {
	addConfigFlags(resetPwdCmd)
	resetPwdCmd.Flags().StringVar(&resetPwdAdmin, "admin", "", `Administrator username whose password to reset`)
	resetPwdCmd.MarkFlagRequired("admin") //nolint:errcheck

	rootCmd.AddCommand(resetPwdCmd)
}
