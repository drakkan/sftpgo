package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/service"
	"github.com/drakkan/sftpgo/v2/util"
)

var (
	startCmd = &cobra.Command{
		Use:   "start",
		Short: "Start the SFTPGo Windows Service",
		Run: func(cmd *cobra.Command, args []string) {
			configDir = util.CleanDirInput(configDir)
			if !filepath.IsAbs(logFilePath) && util.IsFileInputValid(logFilePath) {
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
				LogUTCTime:    logUTCTime,
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
