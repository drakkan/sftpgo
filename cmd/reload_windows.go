package cmd

import (
	"fmt"

	"github.com/drakkan/sftpgo/service"
	"github.com/spf13/cobra"
)

var (
	reloadCmd = &cobra.Command{
		Use:   "reload",
		Short: "Reload the SFTPGo Windows Service sending a \"paramchange\" request",
		Run: func(cmd *cobra.Command, args []string) {
			s := service.WindowsService{
				Service: service.Service{
					Shutdown: make(chan bool),
				},
			}
			err := s.Reload()
			if err != nil {
				fmt.Printf("Error reloading service: %v\r\n", err)
			} else {
				fmt.Printf("Service reloaded!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(reloadCmd)
}
