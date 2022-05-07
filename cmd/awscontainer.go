//go:build awscontainer
// +build awscontainer

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func addAWSContainerFlags(cmd *cobra.Command) {
	viper.SetDefault("disable_aws_installation_code", false)
	viper.BindEnv("disable_aws_installation_code", "SFTPGO_DISABLE_AWS_INSTALLATION_CODE") //nolint:errcheck
	cmd.Flags().BoolVar(&disableAWSInstallationCode, "disable-aws-installation-code", viper.GetBool("disable_aws_installation_code"),
		`Disable installation code for the AWS container.
This flag can be set using
SFTPGO_DISABLE_AWS_INSTALLATION_CODE env var too.
`)
	viper.BindPFlag("disable_aws_installation_code", cmd.Flags().Lookup("disable-aws-installation-code")) //nolint:errcheck
}
