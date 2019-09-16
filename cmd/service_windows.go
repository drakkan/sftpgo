package cmd

import (
	"github.com/spf13/cobra"
)

var (
	serviceCmd = &cobra.Command{
		Use:   "service",
		Short: "Install, Uninstall, Start, Stop and retrieve status for SFTPGo Windows Service",
	}
)

func init() {
	rootCmd.AddCommand(serviceCmd)
}
