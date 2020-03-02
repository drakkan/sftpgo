package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/drakkan/sftpgo/service"
	"github.com/spf13/cobra"
)

var (
	startCmd = &cobra.Command{
		Use:   "start",
		Short: "Start SFTPGo Windows Service",
		Run: func(cmd *cobra.Command, args []string) {
			configDir = filepath.Clean(configDir)
			if !filepath.IsAbs(logFilePath) && len(logFilePath) > 0 && logFilePath != "." {
				logFilePath = filepath.Join(configDir, logFilePath)
			}
			s := service.Service{
				ConfigDir:     configDir,
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
			err := winService.RunService()
			if err != nil {
				fmt.Printf("Error starting service: %v\r\n", err)
			} else {
				fmt.Printf("Service started!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(startCmd)
	addServeFlags(startCmd)
}
