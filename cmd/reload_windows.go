package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/service"
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
				fmt.Printf("Error sending reload signal: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Reload signal sent!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(reloadCmd)
}
