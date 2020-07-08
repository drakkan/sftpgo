package cmd

import "github.com/spf13/cobra"

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "A collection of useful generators",
}

func init() {
	rootCmd.AddCommand(genCmd)
}
