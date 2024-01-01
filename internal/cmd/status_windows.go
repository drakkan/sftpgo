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
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/internal/service"
)

var (
	statusCmd = &cobra.Command{
		Use:   "status",
		Short: "Retrieve the status for the SFTPGo Windows Service",
		Run: func(_ *cobra.Command, _ []string) {
			s := service.WindowsService{
				Service: service.Service{
					Shutdown: make(chan bool),
				},
			}
			status, err := s.Status()
			if err != nil {
				fmt.Printf("Error querying service status: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Service status: %q\r\n", status.String())
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(statusCmd)
}
