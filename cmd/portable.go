package cmd

import (
	"path/filepath"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/service"
	"github.com/spf13/cobra"
)

var (
	directoryToServe    string
	portableSFTPDPort   int
	portableEnableSCP   bool
	portableUsername    string
	portablePassword    string
	portablePublicKeys  []string
	portablePermissions []string
	portableCmd         = &cobra.Command{
		Use:   "portable",
		Short: "Serve a single directory",
		Long: `To serve the current working directory with auto generated credentials simply use:

sftpgo portable

Please take a look at the usage below to customize the serving parameters`,
		Run: func(cmd *cobra.Command, args []string) {
			portableDir := directoryToServe
			if !filepath.IsAbs(portableDir) {
				portableDir, _ = filepath.Abs(portableDir)
			}
			service := service.Service{
				ConfigDir:     defaultConfigDir,
				ConfigFile:    defaultConfigName,
				LogFilePath:   defaultLogFile,
				LogMaxSize:    defaultLogMaxSize,
				LogMaxBackups: defaultLogMaxBackup,
				LogMaxAge:     defaultLogMaxAge,
				LogCompress:   defaultLogCompress,
				LogVerbose:    defaultLogVerbose,
				Shutdown:      make(chan bool),
				PortableMode:  1,
				PortableUser: dataprovider.User{
					Username:    portableUsername,
					Password:    portablePassword,
					PublicKeys:  portablePublicKeys,
					Permissions: portablePermissions,
					HomeDir:     portableDir,
				},
			}
			if err := service.StartPortableMode(portableSFTPDPort, portableEnableSCP); err == nil {
				service.Wait()
			}
		},
	}
)

func init() {
	portableCmd.Flags().StringVarP(&directoryToServe, "directory", "d", ".",
		"Path to the directory to serve. This can be an absolute path or a path relative to the current directory")
	portableCmd.Flags().IntVarP(&portableSFTPDPort, "sftpd-port", "s", 0, "0 means a random non privileged port")
	portableCmd.Flags().BoolVarP(&portableEnableSCP, "scp", "", false, "Enable SCP")
	portableCmd.Flags().StringVarP(&portableUsername, "username", "u", "", "Leave empty to use an auto generated value")
	portableCmd.Flags().StringVarP(&portablePassword, "password", "p", "", "Leave empty to use an auto generated value")
	portableCmd.Flags().StringSliceVarP(&portablePublicKeys, "public-key", "k", []string{}, "")
	portableCmd.Flags().StringSliceVarP(&portablePermissions, "permissions", "g", []string{"list", "download"},
		"User's permissions. \"*\" means any permission")
	rootCmd.AddCommand(portableCmd)
}
