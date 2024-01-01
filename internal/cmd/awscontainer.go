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
