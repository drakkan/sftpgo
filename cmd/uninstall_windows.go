package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/service"
)

var (
	uninstallCmd = &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall SFTPGo Windows Service",
		Run: func(cmd *cobra.Command, args []string) {
			s := service.WindowsService{
				Service: service.Service{
					Shutdown: make(chan bool),
				},
			}
			err := s.Uninstall()
			if err != nil {
				fmt.Printf("Error removing service: %v\r\n", err)
			} else {
				fmt.Printf("Service uninstalled\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(uninstallCmd)
}
