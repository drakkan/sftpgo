package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/service"
)

var (
	stopCmd = &cobra.Command{
		Use:   "stop",
		Short: "Stop the SFTPGo Windows Service",
		Run: func(cmd *cobra.Command, args []string) {
			s := service.WindowsService{
				Service: service.Service{
					Shutdown: make(chan bool),
				},
			}
			err := s.Stop()
			if err != nil {
				fmt.Printf("Error stopping service: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Service stopped!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(stopCmd)
}
