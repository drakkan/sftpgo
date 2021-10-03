package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/service"
)

var (
	uninstallCmd = &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall the SFTPGo Windows Service",
		Run: func(cmd *cobra.Command, args []string) {
			s := service.WindowsService{
				Service: service.Service{
					Shutdown: make(chan bool),
				},
			}
			err := s.Uninstall()
			if err != nil {
				fmt.Printf("Error removing service: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Service uninstalled\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(uninstallCmd)
}
