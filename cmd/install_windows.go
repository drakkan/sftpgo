package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/drakkan/sftpgo/service"
	"github.com/spf13/cobra"
)

var (
	installCmd = &cobra.Command{
		Use:   "install",
		Short: "Install SFTPGo as Windows Service",
		Long: `To install the SFTPGo Windows Service with the default values for the command line flags simply use:

sftpgo service install

Please take a look at the usage below to customize the startup options`,
		Run: func(cmd *cobra.Command, args []string) {
			s := service.Service{
				ConfigDir:     filepath.Clean(configDir),
				ConfigFile:    configFile,
				LogFilePath:   logFilePath,
				LogMaxSize:    logMaxSize,
				LogMaxBackups: logMaxBackups,
				LogMaxAge:     logMaxAge,
				LogCompress:   logCompress,
				LogVerbose:    logVerbose,
				Shutdown:      make(chan bool),
			}
			winService := service.WindowsService{
				Service: s,
			}
			serviceArgs := []string{"service", "start"}
			customFlags := getCustomServeFlags()
			if len(customFlags) > 0 {
				serviceArgs = append(serviceArgs, customFlags...)
			}
			err := winService.Install(serviceArgs...)
			if err != nil {
				fmt.Printf("Error installing service: %v\r\n", err)
			} else {
				fmt.Printf("Service installed!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(installCmd)
	addServeFlags(installCmd)
}
