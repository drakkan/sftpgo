package cmd

import (
	"github.com/spf13/cobra"
)

var (
	serviceCmd = &cobra.Command{
		Use:   "service",
		Short: "Manage the SFTPGo Windows Service",
	}
)

func init() {
	rootCmd.AddCommand(serviceCmd)
}
