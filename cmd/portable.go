// +build !noportable

package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/service"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/version"
	"github.com/drakkan/sftpgo/vfs"
)

var (
	directoryToServe             string
	portableSFTPDPort            int
	portableAdvertiseService     bool
	portableAdvertiseCredentials bool
	portableUsername             string
	portablePassword             string
	portableLogFile              string
	portableLogVerbose           bool
	portablePublicKeys           []string
	portablePermissions          []string
	portableSSHCommands          []string
	portableAllowedPatterns      []string
	portableDeniedPatterns       []string
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
	portableFTPDPort             int
	portableFTPSCert             string
	portableFTPSKey              string
	portableWebDAVPort           int
	portableWebDAVCert           string
	portableWebDAVKey            string
	portableAzContainer          string
	portableAzAccountName        string
	portableAzAccountKey         string
	portableAzEndpoint           string
	portableAzAccessTier         string
	portableAzSASURL             string
	portableAzKeyPrefix          string
	portableAzULPartSize         int
	portableAzULConcurrency      int
	portableAzUseEmulator        bool
	portableCryptPassphrase      string
	portableCmd                  = &cobra.Command{
		Use:   "portable",
		Short: "Serve a single directory",
		Long: `To serve the current working directory with auto generated credentials simply
use:

$ sftpgo portable

Please take a look at the usage below to customize the serving parameters`,
		Run: func(cmd *cobra.Command, args []string) {
			portableDir := directoryToServe
			fsProvider := dataprovider.FilesystemProvider(portableFsProvider)
			if !filepath.IsAbs(portableDir) {
				if fsProvider == dataprovider.LocalFilesystemProvider {
					portableDir, _ = filepath.Abs(portableDir)
				} else {
					portableDir = os.TempDir()
				}
			}
			permissions := make(map[string][]string)
			permissions["/"] = portablePermissions
			var portableGCSCredentials []byte
			if fsProvider == dataprovider.GCSFilesystemProvider && len(portableGCSCredentialsFile) > 0 {
				fi, err := os.Stat(portableGCSCredentialsFile)
				if err != nil {
					fmt.Printf("Invalid GCS credentials file: %v\n", err)
					os.Exit(1)
				}
				if fi.Size() > 1048576 {
					fmt.Printf("Invalid GCS credentials file: %#v is too big %v/1048576 bytes\n", portableGCSCredentialsFile,
						fi.Size())
					os.Exit(1)
				}
				creds, err := ioutil.ReadFile(portableGCSCredentialsFile)
				if err != nil {
					fmt.Printf("Unable to read credentials file: %v\n", err)
				}
				portableGCSCredentials = creds
				portableGCSAutoCredentials = 0
			}
			if portableFTPDPort >= 0 && len(portableFTPSCert) > 0 && len(portableFTPSKey) > 0 {
				_, err := common.NewCertManager(portableFTPSCert, portableFTPSKey, "FTP portable")
				if err != nil {
					fmt.Printf("Unable to load FTPS key pair, cert file %#v key file %#v error: %v\n",
						portableFTPSCert, portableFTPSKey, err)
					os.Exit(1)
				}
			}
			if portableWebDAVPort > 0 && len(portableWebDAVCert) > 0 && len(portableWebDAVKey) > 0 {
				_, err := common.NewCertManager(portableWebDAVCert, portableWebDAVKey, "WebDAV portable")
				if err != nil {
					fmt.Printf("Unable to load WebDAV key pair, cert file %#v key file %#v error: %v\n",
						portableWebDAVCert, portableWebDAVKey, err)
					os.Exit(1)
				}
			}
			service := service.Service{
				ConfigDir:     filepath.Clean(defaultConfigDir),
				ConfigFile:    defaultConfigFile,
				LogFilePath:   portableLogFile,
				LogMaxSize:    defaultLogMaxSize,
				LogMaxBackups: defaultLogMaxBackup,
				LogMaxAge:     defaultLogMaxAge,
				LogCompress:   defaultLogCompress,
				LogVerbose:    portableLogVerbose,
				Profiler:      defaultProfiler,
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
						Provider: dataprovider.FilesystemProvider(portableFsProvider),
						S3Config: vfs.S3FsConfig{
							Bucket:            portableS3Bucket,
							Region:            portableS3Region,
							AccessKey:         portableS3AccessKey,
							AccessSecret:      kms.NewPlainSecret(portableS3AccessSecret),
							Endpoint:          portableS3Endpoint,
							StorageClass:      portableS3StorageClass,
							KeyPrefix:         portableS3KeyPrefix,
							UploadPartSize:    int64(portableS3ULPartSize),
							UploadConcurrency: portableS3ULConcurrency,
						},
						GCSConfig: vfs.GCSFsConfig{
							Bucket:               portableGCSBucket,
							Credentials:          kms.NewPlainSecret(string(portableGCSCredentials)),
							AutomaticCredentials: portableGCSAutoCredentials,
							StorageClass:         portableGCSStorageClass,
							KeyPrefix:            portableGCSKeyPrefix,
						},
						AzBlobConfig: vfs.AzBlobFsConfig{
							Container:         portableAzContainer,
							AccountName:       portableAzAccountName,
							AccountKey:        kms.NewPlainSecret(portableAzAccountKey),
							Endpoint:          portableAzEndpoint,
							AccessTier:        portableAzAccessTier,
							SASURL:            portableAzSASURL,
							KeyPrefix:         portableAzKeyPrefix,
							UseEmulator:       portableAzUseEmulator,
							UploadPartSize:    int64(portableAzULPartSize),
							UploadConcurrency: portableAzULConcurrency,
						},
						CryptConfig: vfs.CryptFsConfig{
							Passphrase: kms.NewPlainSecret(portableCryptPassphrase),
						},
					},
					Filters: dataprovider.UserFilters{
						FilePatterns: parsePatternsFilesFilters(),
					},
				},
			}
			if err := service.StartPortableMode(portableSFTPDPort, portableFTPDPort, portableWebDAVPort, portableSSHCommands, portableAdvertiseService,
				portableAdvertiseCredentials, portableFTPSCert, portableFTPSKey, portableWebDAVCert, portableWebDAVKey); err == nil {
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
	version.AddFeature("+portable")

	portableCmd.Flags().StringVarP(&directoryToServe, "directory", "d", ".", `Path to the directory to serve.
This can be an absolute path or a path
relative to the current directory
`)
	portableCmd.Flags().IntVarP(&portableSFTPDPort, "sftpd-port", "s", 0, `0 means a random unprivileged port,
< 0 disabled`)
	portableCmd.Flags().IntVar(&portableFTPDPort, "ftpd-port", -1, `0 means a random unprivileged port,
< 0 disabled`)
	portableCmd.Flags().IntVar(&portableWebDAVPort, "webdav-port", -1, `0 means a random unprivileged port,
< 0 disabled`)
	portableCmd.Flags().StringSliceVarP(&portableSSHCommands, "ssh-commands", "c", sftpd.GetDefaultSSHCommands(),
		`SSH commands to enable.
"*" means any supported SSH command
including scp
`)
	portableCmd.Flags().StringVarP(&portableUsername, "username", "u", "", `Leave empty to use an auto generated
value`)
	portableCmd.Flags().StringVarP(&portablePassword, "password", "p", "", `Leave empty to use an auto generated
value`)
	portableCmd.Flags().StringVarP(&portableLogFile, logFilePathFlag, "l", "", "Leave empty to disable logging")
	portableCmd.Flags().BoolVarP(&portableLogVerbose, logVerboseFlag, "v", false, "Enable verbose logs")
	portableCmd.Flags().StringSliceVarP(&portablePublicKeys, "public-key", "k", []string{}, "")
	portableCmd.Flags().StringSliceVarP(&portablePermissions, "permissions", "g", []string{"list", "download"},
		`User's permissions. "*" means any
permission`)
	portableCmd.Flags().StringArrayVar(&portableAllowedPatterns, "allowed-patterns", []string{},
		`Allowed file patterns case insensitive.
The format is:
/dir::pattern1,pattern2.
For example: "/somedir::*.jpg,a*b?.png"`)
	portableCmd.Flags().StringArrayVar(&portableDeniedPatterns, "denied-patterns", []string{},
		`Denied file patterns case insensitive.
The format is:
/dir::pattern1,pattern2.
For example: "/somedir::*.jpg,a*b?.png"`)
	portableCmd.Flags().BoolVarP(&portableAdvertiseService, "advertise-service", "S", false,
		`Advertise configured services using
multicast DNS`)
	portableCmd.Flags().BoolVarP(&portableAdvertiseCredentials, "advertise-credentials", "C", false,
		`If the SFTP/FTP service is
advertised via multicast DNS, this
flag allows to put username/password
inside the advertised TXT record`)
	portableCmd.Flags().IntVarP(&portableFsProvider, "fs-provider", "f", int(dataprovider.LocalFilesystemProvider), `0 => local filesystem
1 => AWS S3 compatible
2 => Google Cloud Storage
3 => Azure Blob Storage
4 => Encrypted local filesystem`)
	portableCmd.Flags().StringVar(&portableS3Bucket, "s3-bucket", "", "")
	portableCmd.Flags().StringVar(&portableS3Region, "s3-region", "", "")
	portableCmd.Flags().StringVar(&portableS3AccessKey, "s3-access-key", "", "")
	portableCmd.Flags().StringVar(&portableS3AccessSecret, "s3-access-secret", "", "")
	portableCmd.Flags().StringVar(&portableS3Endpoint, "s3-endpoint", "", "")
	portableCmd.Flags().StringVar(&portableS3StorageClass, "s3-storage-class", "", "")
	portableCmd.Flags().StringVar(&portableS3KeyPrefix, "s3-key-prefix", "", `Allows to restrict access to the
virtual folder identified by this
prefix and its contents`)
	portableCmd.Flags().IntVar(&portableS3ULPartSize, "s3-upload-part-size", 5, `The buffer size for multipart uploads
(MB)`)
	portableCmd.Flags().IntVar(&portableS3ULConcurrency, "s3-upload-concurrency", 2, `How many parts are uploaded in
parallel`)
	portableCmd.Flags().StringVar(&portableGCSBucket, "gcs-bucket", "", "")
	portableCmd.Flags().StringVar(&portableGCSStorageClass, "gcs-storage-class", "", "")
	portableCmd.Flags().StringVar(&portableGCSKeyPrefix, "gcs-key-prefix", "", `Allows to restrict access to the
virtual folder identified by this
prefix and its contents`)
	portableCmd.Flags().StringVar(&portableGCSCredentialsFile, "gcs-credentials-file", "", `Google Cloud Storage JSON credentials
file`)
	portableCmd.Flags().IntVar(&portableGCSAutoCredentials, "gcs-automatic-credentials", 1, `0 means explicit credentials using
a JSON credentials file, 1 automatic
`)
	portableCmd.Flags().StringVar(&portableFTPSCert, "ftpd-cert", "", "Path to the certificate file for FTPS")
	portableCmd.Flags().StringVar(&portableFTPSKey, "ftpd-key", "", "Path to the key file for FTPS")
	portableCmd.Flags().StringVar(&portableWebDAVCert, "webdav-cert", "", `Path to the certificate file for WebDAV
over HTTPS`)
	portableCmd.Flags().StringVar(&portableWebDAVKey, "webdav-key", "", `Path to the key file for WebDAV over
HTTPS`)
	portableCmd.Flags().StringVar(&portableAzContainer, "az-container", "", "")
	portableCmd.Flags().StringVar(&portableAzAccountName, "az-account-name", "", "")
	portableCmd.Flags().StringVar(&portableAzAccountKey, "az-account-key", "", "")
	portableCmd.Flags().StringVar(&portableAzSASURL, "az-sas-url", "", `Shared access signature URL`)
	portableCmd.Flags().StringVar(&portableAzEndpoint, "az-endpoint", "", `Leave empty to use the default:
"blob.core.windows.net"`)
	portableCmd.Flags().StringVar(&portableAzAccessTier, "az-access-tier", "", `Leave empty to use the default
container setting`)
	portableCmd.Flags().StringVar(&portableAzKeyPrefix, "az-key-prefix", "", `Allows to restrict access to the
virtual folder identified by this
prefix and its contents`)
	portableCmd.Flags().IntVar(&portableAzULPartSize, "az-upload-part-size", 4, `The buffer size for multipart uploads
(MB)`)
	portableCmd.Flags().IntVar(&portableAzULConcurrency, "az-upload-concurrency", 2, `How many parts are uploaded in
parallel`)
	portableCmd.Flags().BoolVar(&portableAzUseEmulator, "az-use-emulator", false, "")
	portableCmd.Flags().StringVar(&portableCryptPassphrase, "crypto-passphrase", "", `Passphrase for encryption/decryption`)
	rootCmd.AddCommand(portableCmd)
}

func parsePatternsFilesFilters() []dataprovider.PatternsFilter {
	var patterns []dataprovider.PatternsFilter
	for _, val := range portableAllowedPatterns {
		p, exts := getPatternsFilterValues(strings.TrimSpace(val))
		if len(p) > 0 {
			patterns = append(patterns, dataprovider.PatternsFilter{
				Path:            path.Clean(p),
				AllowedPatterns: exts,
				DeniedPatterns:  []string{},
			})
		}
	}
	for _, val := range portableDeniedPatterns {
		p, exts := getPatternsFilterValues(strings.TrimSpace(val))
		if len(p) > 0 {
			found := false
			for index, e := range patterns {
				if path.Clean(e.Path) == path.Clean(p) {
					patterns[index].DeniedPatterns = append(patterns[index].DeniedPatterns, exts...)
					found = true
					break
				}
			}
			if !found {
				patterns = append(patterns, dataprovider.PatternsFilter{
					Path:            path.Clean(p),
					AllowedPatterns: []string{},
					DeniedPatterns:  exts,
				})
			}
		}
	}
	return patterns
}

func getPatternsFilterValues(value string) (string, []string) {
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
			if dir != "" && len(exts) > 0 {
				return dir, exts
			}
		}
	}
	return "", nil
}
