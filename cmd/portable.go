package cmd

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

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
	portableAllowedExtensions    []string
	portableDeniedExtensions     []string
	portableFsProvider           int
	portableS3Bucket             string
	portableS3Region             string
	portableS3AccessKey          string
	portableS3AccessSecret       string
	portableS3Endpoint           string
	portableS3StorageClass       string
	portableS3KeyPrefix          string
	portableS3ULPartSize         int
	portableS3ULConcurrency      int
	portableGCSBucket            string
	portableGCSCredentialsFile   string
	portableGCSAutoCredentials   int
	portableGCSStorageClass      string
	portableGCSKeyPrefix         string
	portableCmd                  = &cobra.Command{
		Use:   "portable",
		Short: "Serve a single directory",
		Long: `To serve the current working directory with auto generated credentials simply use:

sftpgo portable

Please take a look at the usage below to customize the serving parameters`,
		Run: func(cmd *cobra.Command, args []string) {
			portableDir := directoryToServe
			if !filepath.IsAbs(portableDir) {
				if portableFsProvider == 0 {
					portableDir, _ = filepath.Abs(portableDir)
				} else {
					portableDir = os.TempDir()
				}
			}
			permissions := make(map[string][]string)
			permissions["/"] = portablePermissions
			portableGCSCredentials := ""
			if portableFsProvider == 2 && len(portableGCSCredentialsFile) > 0 {
				fi, err := os.Stat(portableGCSCredentialsFile)
				if err != nil {
					fmt.Printf("Invalid GCS credentials file: %v\n", err)
					return
				}
				if fi.Size() > 1048576 {
					fmt.Printf("Invalid GCS credentials file: %#v is too big %v/1048576 bytes\n", portableGCSCredentialsFile,
						fi.Size())
					return
				}
				creds, err := ioutil.ReadFile(portableGCSCredentialsFile)
				if err != nil {
					fmt.Printf("Unable to read credentials file: %v\n", err)
				}
				portableGCSCredentials = base64.StdEncoding.EncodeToString(creds)
				portableGCSAutoCredentials = 0
			}
			service := service.Service{
				ConfigDir:     filepath.Clean(defaultConfigDir),
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
							Bucket:            portableS3Bucket,
							Region:            portableS3Region,
							AccessKey:         portableS3AccessKey,
							AccessSecret:      portableS3AccessSecret,
							Endpoint:          portableS3Endpoint,
							StorageClass:      portableS3StorageClass,
							KeyPrefix:         portableS3KeyPrefix,
							UploadPartSize:    int64(portableS3ULPartSize),
							UploadConcurrency: portableS3ULConcurrency,
						},
						GCSConfig: vfs.GCSFsConfig{
							Bucket:               portableGCSBucket,
							Credentials:          portableGCSCredentials,
							AutomaticCredentials: portableGCSAutoCredentials,
							StorageClass:         portableGCSStorageClass,
							KeyPrefix:            portableGCSKeyPrefix,
						},
					},
					Filters: dataprovider.UserFilters{
						FileExtensions: parseFileExtensionsFilters(),
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
	portableCmd.Flags().StringArrayVar(&portableAllowedExtensions, "allowed-extensions", []string{},
		"Allowed file extensions case insensitive. The format is /dir::ext1,ext2. For example: \"/somedir::.jpg,.png\"")
	portableCmd.Flags().StringArrayVar(&portableDeniedExtensions, "denied-extensions", []string{},
		"Denied file extensions case insensitive. The format is /dir::ext1,ext2. For example: \"/somedir::.jpg,.png\"")
	portableCmd.Flags().BoolVarP(&portableAdvertiseService, "advertise-service", "S", true,
		"Advertise SFTP service using multicast DNS")
	portableCmd.Flags().BoolVarP(&portableAdvertiseCredentials, "advertise-credentials", "C", false,
		"If the SFTP service is advertised via multicast DNS, this flag allows to put username/password inside the advertised TXT record")
	portableCmd.Flags().IntVarP(&portableFsProvider, "fs-provider", "f", 0, "0 means local filesystem, 1 Amazon S3 compatible, "+
		"2 Google Cloud Storage")
	portableCmd.Flags().StringVar(&portableS3Bucket, "s3-bucket", "", "")
	portableCmd.Flags().StringVar(&portableS3Region, "s3-region", "", "")
	portableCmd.Flags().StringVar(&portableS3AccessKey, "s3-access-key", "", "")
	portableCmd.Flags().StringVar(&portableS3AccessSecret, "s3-access-secret", "", "")
	portableCmd.Flags().StringVar(&portableS3Endpoint, "s3-endpoint", "", "")
	portableCmd.Flags().StringVar(&portableS3StorageClass, "s3-storage-class", "", "")
	portableCmd.Flags().StringVar(&portableS3KeyPrefix, "s3-key-prefix", "", "Allows to restrict access to the virtual folder "+
		"identified by this prefix and its contents")
	portableCmd.Flags().IntVar(&portableS3ULPartSize, "s3-upload-part-size", 5, "The buffer size for multipart uploads (MB)")
	portableCmd.Flags().IntVar(&portableS3ULConcurrency, "s3-upload-concurrency", 2, "How many parts are uploaded in parallel")
	portableCmd.Flags().StringVar(&portableGCSBucket, "gcs-bucket", "", "")
	portableCmd.Flags().StringVar(&portableGCSStorageClass, "gcs-storage-class", "", "")
	portableCmd.Flags().StringVar(&portableGCSKeyPrefix, "gcs-key-prefix", "", "Allows to restrict access to the virtual folder "+
		"identified by this prefix and its contents")
	portableCmd.Flags().StringVar(&portableGCSCredentialsFile, "gcs-credentials-file", "", "Google Cloud Storage JSON credentials file")
	portableCmd.Flags().IntVar(&portableGCSAutoCredentials, "gcs-automatic-credentials", 1, "0 means explicit credentials using a JSON "+
		"credentials file, 1 automatic")
	rootCmd.AddCommand(portableCmd)
}

func parseFileExtensionsFilters() []dataprovider.ExtensionsFilter {
	var extensions []dataprovider.ExtensionsFilter
	for _, val := range portableAllowedExtensions {
		p, exts := getExtensionsFilterValues(strings.TrimSpace(val))
		if len(p) > 0 {
			extensions = append(extensions, dataprovider.ExtensionsFilter{
				Path:              path.Clean(p),
				AllowedExtensions: exts,
				DeniedExtensions:  []string{},
			})
		}
	}
	for _, val := range portableDeniedExtensions {
		p, exts := getExtensionsFilterValues(strings.TrimSpace(val))
		if len(p) > 0 {
			found := false
			for index, e := range extensions {
				if path.Clean(e.Path) == path.Clean(p) {
					extensions[index].DeniedExtensions = append(extensions[index].DeniedExtensions, exts...)
					found = true
					break
				}
			}
			if !found {
				extensions = append(extensions, dataprovider.ExtensionsFilter{
					Path:              path.Clean(p),
					AllowedExtensions: []string{},
					DeniedExtensions:  exts,
				})
			}
		}
	}
	return extensions
}

func getExtensionsFilterValues(value string) (string, []string) {
	if strings.Contains(value, "::") {
		dirExts := strings.Split(value, "::")
		if len(dirExts) > 1 {
			dir := strings.TrimSpace(dirExts[0])
			exts := []string{}
			for _, e := range strings.Split(dirExts[1], ",") {
				cleanedExt := strings.TrimSpace(e)
				if len(cleanedExt) > 0 {
					exts = append(exts, cleanedExt)
				}
			}
			if len(dir) > 0 && len(exts) > 0 {
				return dir, exts
			}
		}
	}
	return "", nil
}
