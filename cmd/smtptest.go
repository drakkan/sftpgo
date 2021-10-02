package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/smtp"
	"github.com/drakkan/sftpgo/v2/util"
)

var (
	smtpTestRecipient string
	smtpTestCmd       = &cobra.Command{
		Use:   "smtptest",
		Short: "Test the SMTP configuration",
		Long: `SFTPGo will try to send a test email to the specified recipient.
If the SMTP configuration is correct you should receive this email.`,
		Run: func(cmd *cobra.Command, args []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			configDir = util.CleanDirInput(configDir)
			err := config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.WarnToConsole("Unable to initialize data provider, config load error: %v", err)
				os.Exit(1)
			}
			smtpConfig := config.GetSMTPConfig()
			err = smtpConfig.Initialize(configDir)
			if err != nil {
				logger.ErrorToConsole("unable to initialize SMTP configuration: %v", err)
				os.Exit(1)
			}
			err = smtp.SendEmail(smtpTestRecipient, "SFTPGo - Testing Email Settings", "It appears your SFTPGo email is setup correctly!",
				smtp.EmailContentTypeTextPlain)
			if err != nil {
				logger.WarnToConsole("Error sending email: %v", err)
				os.Exit(1)
			}
			logger.InfoToConsole("No errors were reported while sending an email. Please check your inbox to make sure.")
		},
	}
)

func init() {
	addConfigFlags(smtpTestCmd)
	smtpTestCmd.Flags().StringVar(&smtpTestRecipient, "recipient", "", `email address to send the test e-mail to`)
	smtpTestCmd.MarkFlagRequired("recipient") //nolint:errcheck

	rootCmd.AddCommand(smtpTestCmd)
}
