package cmd

import (
	"github.com/drakkan/sftpgo/service"
	"github.com/drakkan/sftpgo/utils"
	"github.com/spf13/cobra"
)

var (
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the SFTP Server",
		Long: `To start the SFTPGo with the default values for the command line flags simply use:

sftpgo serve

Please take a look at the usage below to customize the startup options`,
		Run: func(cmd *cobra.Command, args []string) {
			service := service.Service{
				ConfigDir:     utils.CleanDirInput(configDir),
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
			if err := service.Start(); err == nil {
				service.Wait()
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(serveCmd)
	addServeFlags(serveCmd)
}
