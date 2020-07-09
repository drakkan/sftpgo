package cmd

import (
	"github.com/spf13/cobra"
)

var (
	serviceCmd = &cobra.Command{
		Use:   "service",
		Short: "Manage SFTPGo Windows Service",
	}
)

func init() {
	rootCmd.AddCommand(serviceCmd)
}
