package cmd

import (
	"fmt"

	"github.com/drakkan/sftpgo/service"
	"github.com/spf13/cobra"
)

var (
	stopCmd = &cobra.Command{
		Use:   "stop",
		Short: "Stop SFTPGo Windows Service",
		Run: func(cmd *cobra.Command, args []string) {
			s := service.WindowsService{
				Service: service.Service{
					Shutdown: make(chan bool),
				},
			}
			err := s.Stop()
			if err != nil {
				fmt.Printf("Error stopping service: %v\r\n", err)
			} else {
				fmt.Printf("Service stopped!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(stopCmd)
}
