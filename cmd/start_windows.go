package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/service"
	"github.com/drakkan/sftpgo/utils"
)

var (
	startCmd = &cobra.Command{
		Use:   "start",
		Short: "Start SFTPGo Windows Service",
		Run: func(cmd *cobra.Command, args []string) {
			configDir = utils.CleanDirInput(configDir)
			if !filepath.IsAbs(logFilePath) && utils.IsFileInputValid(logFilePath) {
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
				Profiler:      profiler,
				Shutdown:      make(chan bool),
			}
			winService := service.WindowsService{
				Service: s,
			}
			err := winService.RunService()
			if err != nil {
				fmt.Printf("Error starting service: %v\r\n", err)
				os.Exit(1)
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
