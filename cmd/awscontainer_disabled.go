//go:build !awscontainer
// +build !awscontainer

package cmd

import (
	"github.com/spf13/cobra"
)

func addAWSContainerFlags(cmd *cobra.Command) {}
