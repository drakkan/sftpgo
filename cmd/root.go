package cmd

import (
	"fmt"
	"os"

	"github.com/drakkan/sftpgo/utils"
	"github.com/spf13/cobra"
)

const (
	logSender = "cmd"
)

var (
	rootCmd = &cobra.Command{
		Use:   "sftpgo",
		Short: "Full featured and highly configurable SFTP server",
	}
)

func init() {
	rootCmd.Flags().BoolP("version", "v", false, "")
	rootCmd.Version = utils.GetAppVersion()
	rootCmd.SetVersionTemplate(`{{printf "SFTPGo version "}}{{printf "%s" .Version}}
`)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
