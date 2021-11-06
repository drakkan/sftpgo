package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/service"
	"github.com/drakkan/sftpgo/v2/util"
)

var (
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the SFTPGo service",
		Long: `To start the SFTPGo with the default values for the command line flags simply
use:

$ sftpgo serve

Please take a look at the usage below to customize the startup options`,
		Run: func(cmd *cobra.Command, args []string) {
			service := service.Service{
				ConfigDir:         util.CleanDirInput(configDir),
				ConfigFile:        configFile,
				LogFilePath:       logFilePath,
				LogMaxSize:        logMaxSize,
				LogMaxBackups:     logMaxBackups,
				LogMaxAge:         logMaxAge,
				LogCompress:       logCompress,
				LogVerbose:        logVerbose,
				LogUTCTime:        logUTCTime,
				LoadDataFrom:      loadDataFrom,
				LoadDataMode:      loadDataMode,
				LoadDataQuotaScan: loadDataQuotaScan,
				LoadDataClean:     loadDataClean,
				Shutdown:          make(chan bool),
			}
			if err := service.Start(); err == nil {
				service.Wait()
				if service.Error == nil {
					os.Exit(0)
				}
			}
			os.Exit(1)
		},
	}
)

func init() {
	rootCmd.AddCommand(serveCmd)
	addServeFlags(serveCmd)
}
