package cmd

import (
	"path/filepath"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/service"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/vfs"
	"github.com/spf13/cobra"
)

var (
	directoryToServe             string
	portableSFTPDPort            int
	portableAdvertiseService     bool
	portableAdvertiseCredentials bool
	portableUsername             string
	portablePassword             string
	portableLogFile              string
	portablePublicKeys           []string
	portablePermissions          []string
	portableSSHCommands          []string
	portableFsProvider           int
	portableS3Bucket             string
	portableS3Region             string
	portableS3AccessKey          string
	portableS3AccessSecret       string
	portableS3Endpoint           string
	portableS3StorageClass       string
	portableCmd                  = &cobra.Command{
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
			permissions := make(map[string][]string)
			permissions["/"] = portablePermissions
			service := service.Service{
				ConfigDir:     defaultConfigDir,
				ConfigFile:    defaultConfigName,
				LogFilePath:   portableLogFile,
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
					Permissions: permissions,
					HomeDir:     portableDir,
					Status:      1,
					FsConfig: dataprovider.Filesystem{
						Provider: portableFsProvider,
						S3Config: vfs.S3FsConfig{
							Bucket:       portableS3Bucket,
							Region:       portableS3Region,
							AccessKey:    portableS3AccessKey,
							AccessSecret: portableS3AccessSecret,
							Endpoint:     portableS3Endpoint,
							StorageClass: portableS3StorageClass,
						},
					},
				},
			}
			if err := service.StartPortableMode(portableSFTPDPort, portableSSHCommands, portableAdvertiseService,
				portableAdvertiseCredentials); err == nil {
				service.Wait()
			}
		},
	}
)

func init() {
	portableCmd.Flags().StringVarP(&directoryToServe, "directory", "d", ".",
		"Path to the directory to serve. This can be an absolute path or a path relative to the current directory")
	portableCmd.Flags().IntVarP(&portableSFTPDPort, "sftpd-port", "s", 0, "0 means a random non privileged port")
	portableCmd.Flags().StringSliceVarP(&portableSSHCommands, "ssh-commands", "c", sftpd.GetDefaultSSHCommands(),
		"SSH commands to enable. \"*\" means any supported SSH command including scp")
	portableCmd.Flags().StringVarP(&portableUsername, "username", "u", "", "Leave empty to use an auto generated value")
	portableCmd.Flags().StringVarP(&portablePassword, "password", "p", "", "Leave empty to use an auto generated value")
	portableCmd.Flags().StringVarP(&portableLogFile, logFilePathFlag, "l", "", "Leave empty to disable logging")
	portableCmd.Flags().StringSliceVarP(&portablePublicKeys, "public-key", "k", []string{}, "")
	portableCmd.Flags().StringSliceVarP(&portablePermissions, "permissions", "g", []string{"list", "download"},
		"User's permissions. \"*\" means any permission")
	portableCmd.Flags().BoolVarP(&portableAdvertiseService, "advertise-service", "S", true,
		"Advertise SFTP service using multicast DNS")
	portableCmd.Flags().BoolVarP(&portableAdvertiseCredentials, "advertise-credentials", "C", false,
		"If the SFTP service is advertised via multicast DNS this flag allows to put username/password inside the advertised TXT record")
	portableCmd.Flags().IntVarP(&portableFsProvider, "fs-provider", "f", 0, "0 means local filesystem, 1 S3 compatible")
	portableCmd.Flags().StringVar(&portableS3Bucket, "s3-bucket", "", "")
	portableCmd.Flags().StringVar(&portableS3Region, "s3-region", "", "")
	portableCmd.Flags().StringVar(&portableS3AccessKey, "s3-access-key", "", "")
	portableCmd.Flags().StringVar(&portableS3AccessSecret, "s3-access-secret", "", "")
	portableCmd.Flags().StringVar(&portableS3Endpoint, "s3-endpoint", "", "")
	portableCmd.Flags().StringVar(&portableS3StorageClass, "s3-storage-class", "", "")
	rootCmd.AddCommand(portableCmd)
}
