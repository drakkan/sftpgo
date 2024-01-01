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

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/version"
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
		Run: func(cmd *cobra.Command, _ []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			if _, err := os.Stat(manDir); errors.Is(err, fs.ErrNotExist) {
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
