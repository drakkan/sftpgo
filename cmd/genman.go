package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/version"
)

var (
	manDir    string
	genManCmd = &cobra.Command{
		Use:   "man",
		Short: "Generate man pages for sftpgo",
		Long: `This command automatically generates up-to-date man pages of SFTPGo's
command-line interface.
By default, it creates the man page files in the "man" directory under the
current directory.
`,
		Run: func(cmd *cobra.Command, args []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			if _, err := os.Stat(manDir); os.IsNotExist(err) {
				err = os.MkdirAll(manDir, os.ModePerm)
				if err != nil {
					logger.WarnToConsole("Unable to generate man page files: %v", err)
					os.Exit(1)
				}
			}
			header := &doc.GenManHeader{
				Section: "1",
				Manual:  "SFTPGo Manual",
				Source:  fmt.Sprintf("SFTPGo %v", version.Get().Version),
			}
			cmd.Root().DisableAutoGenTag = true
			err := doc.GenManTree(cmd.Root(), header, manDir)
			if err != nil {
				logger.WarnToConsole("Unable to generate man page files: %v", err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	genManCmd.Flags().StringVarP(&manDir, "dir", "d", "man", "The directory to write the man pages")
	genCmd.AddCommand(genManCmd)
}
