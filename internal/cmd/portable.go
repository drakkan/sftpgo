// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build !noportable
// +build !noportable

package cmd

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sftpgo/sdk"
	"github.com/spf13/cobra"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/service"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

var (
	directoryToServe                   string
	portableSFTPDPort                  int
	portableUsername                   string
	portablePassword                   string
	portablePasswordFile               string
	portableStartDir                   string
	portableLogFile                    string
	portableLogLevel                   string
	portableLogUTCTime                 bool
	portablePublicKeys                 []string
	portablePermissions                []string
	portableSSHCommands                []string
	portableAllowedPatterns            []string
	portableDeniedPatterns             []string
	portableFsProvider                 string
	portableS3Bucket                   string
	portableS3Region                   string
	portableS3AccessKey                string
	portableS3AccessSecret             string
	portableS3RoleARN                  string
	portableS3Endpoint                 string
	portableS3StorageClass             string
	portableS3ACL                      string
	portableS3KeyPrefix                string
	portableS3ULPartSize               int
	portableS3ULConcurrency            int
	portableS3ForcePathStyle           bool
	portableS3SkipTLSVerify            bool
	portableGCSBucket                  string
	portableGCSCredentialsFile         string
	portableGCSAutoCredentials         int
	portableGCSStorageClass            string
	portableGCSKeyPrefix               string
	portableFTPDPort                   int
	portableFTPSCert                   string
	portableFTPSKey                    string
	portableWebDAVPort                 int
	portableWebDAVCert                 string
	portableWebDAVKey                  string
	portableHTTPPort                   int
	portableHTTPSCert                  string
	portableHTTPSKey                   string
	portableAzContainer                string
	portableAzAccountName              string
	portableAzAccountKey               string
	portableAzEndpoint                 string
	portableAzAccessTier               string
	portableAzSASURL                   string
	portableAzKeyPrefix                string
	portableAzULPartSize               int
	portableAzULConcurrency            int
	portableAzDLPartSize               int
	portableAzDLConcurrency            int
	portableAzUseEmulator              bool
	portableCryptPassphrase            string
	portableSFTPEndpoint               string
	portableSFTPUsername               string
	portableSFTPPassword               string
	portableSFTPPrivateKeyPath         string
	portableSFTPFingerprints           []string
	portableSFTPPrefix                 string
	portableSFTPDisableConcurrentReads bool
	portableSFTPDBufferSize            int64
	portableCmd                        = &cobra.Command{
		Use:   "portable",
		Short: "Serve a single directory/account",
		Long: `To serve the current working directory with auto generated credentials simply
use:

$ sftpgo portable

Please take a look at the usage below to customize the serving parameters`,
		Run: func(_ *cobra.Command, _ []string) {
			portableDir := directoryToServe
			fsProvider := sdk.GetProviderByName(portableFsProvider)
			if !filepath.IsAbs(portableDir) {
				if fsProvider == sdk.LocalFilesystemProvider {
					portableDir, _ = filepath.Abs(portableDir)
				} else {
					portableDir = os.TempDir()
				}
			}
			permissions := make(map[string][]string)
			permissions["/"] = portablePermissions
			portableGCSCredentials := ""
			if fsProvider == sdk.GCSFilesystemProvider && portableGCSCredentialsFile != "" {
				contents, err := getFileContents(portableGCSCredentialsFile)
				if err != nil {
					fmt.Printf("Unable to get GCS credentials: %v\n", err)
					os.Exit(1)
				}
				portableGCSCredentials = contents
				portableGCSAutoCredentials = 0
			}
			portableSFTPPrivateKey := ""
			if fsProvider == sdk.SFTPFilesystemProvider && portableSFTPPrivateKeyPath != "" {
				contents, err := getFileContents(portableSFTPPrivateKeyPath)
				if err != nil {
					fmt.Printf("Unable to get SFTP private key: %v\n", err)
					os.Exit(1)
				}
				portableSFTPPrivateKey = contents
			}
			if portableFTPDPort >= 0 && portableFTPSCert != "" && portableFTPSKey != "" {
				keyPairs := []common.TLSKeyPair{
					{
						Cert: portableFTPSCert,
						Key:  portableFTPSKey,
						ID:   common.DefaultTLSKeyPaidID,
					},
				}
				_, err := common.NewCertManager(keyPairs, filepath.Clean(defaultConfigDir),
					"FTP portable")
				if err != nil {
					fmt.Printf("Unable to load FTPS key pair, cert file %q key file %q error: %v\n",
						portableFTPSCert, portableFTPSKey, err)
					os.Exit(1)
				}
			}
			if portableWebDAVPort >= 0 && portableWebDAVCert != "" && portableWebDAVKey != "" {
				keyPairs := []common.TLSKeyPair{
					{
						Cert: portableWebDAVCert,
						Key:  portableWebDAVKey,
						ID:   common.DefaultTLSKeyPaidID,
					},
				}
				_, err := common.NewCertManager(keyPairs, filepath.Clean(defaultConfigDir),
					"WebDAV portable")
				if err != nil {
					fmt.Printf("Unable to load WebDAV key pair, cert file %q key file %q error: %v\n",
						portableWebDAVCert, portableWebDAVKey, err)
					os.Exit(1)
				}
			}
			if portableHTTPPort >= 0 && portableHTTPSCert != "" && portableHTTPSKey != "" {
				keyPairs := []common.TLSKeyPair{
					{
						Cert: portableHTTPSCert,
						Key:  portableHTTPSKey,
						ID:   common.DefaultTLSKeyPaidID,
					},
				}
				_, err := common.NewCertManager(keyPairs, filepath.Clean(defaultConfigDir),
					"HTTP portable")
				if err != nil {
					fmt.Printf("Unable to load HTTPS key pair, cert file %q key file %q error: %v\n",
						portableHTTPSCert, portableHTTPSKey, err)
					os.Exit(1)
				}
			}
			pwd := portablePassword
			if portablePasswordFile != "" {
				content, err := os.ReadFile(portablePasswordFile)
				if err != nil {
					fmt.Printf("Unable to read password file %q: %v", portablePasswordFile, err)
					os.Exit(1)
				}
				pwd = strings.TrimSpace(string(content))
			}
			service.SetGraceTime(graceTime)
			service := service.Service{
				ConfigDir:     util.CleanDirInput(configDir),
				ConfigFile:    configFile,
				LogFilePath:   portableLogFile,
				LogMaxSize:    defaultLogMaxSize,
				LogMaxBackups: defaultLogMaxBackup,
				LogMaxAge:     defaultLogMaxAge,
				LogCompress:   defaultLogCompress,
				LogLevel:      portableLogLevel,
				LogUTCTime:    portableLogUTCTime,
				Shutdown:      make(chan bool),
				PortableMode:  1,
				PortableUser: dataprovider.User{
					BaseUser: sdk.BaseUser{
						Username:    portableUsername,
						Password:    pwd,
						PublicKeys:  portablePublicKeys,
						Permissions: permissions,
						HomeDir:     portableDir,
						Status:      1,
					},
					Filters: dataprovider.UserFilters{
						BaseUserFilters: sdk.BaseUserFilters{
							FilePatterns:   parsePatternsFilesFilters(),
							StartDirectory: portableStartDir,
						},
					},
					FsConfig: vfs.Filesystem{
						Provider: sdk.GetProviderByName(portableFsProvider),
						S3Config: vfs.S3FsConfig{
							BaseS3FsConfig: sdk.BaseS3FsConfig{
								Bucket:            portableS3Bucket,
								Region:            portableS3Region,
								AccessKey:         portableS3AccessKey,
								RoleARN:           portableS3RoleARN,
								Endpoint:          portableS3Endpoint,
								StorageClass:      portableS3StorageClass,
								ACL:               portableS3ACL,
								KeyPrefix:         portableS3KeyPrefix,
								UploadPartSize:    int64(portableS3ULPartSize),
								UploadConcurrency: portableS3ULConcurrency,
								ForcePathStyle:    portableS3ForcePathStyle,
								SkipTLSVerify:     portableS3SkipTLSVerify,
							},
							AccessSecret: kms.NewPlainSecret(portableS3AccessSecret),
						},
						GCSConfig: vfs.GCSFsConfig{
							BaseGCSFsConfig: sdk.BaseGCSFsConfig{
								Bucket:               portableGCSBucket,
								AutomaticCredentials: portableGCSAutoCredentials,
								StorageClass:         portableGCSStorageClass,
								KeyPrefix:            portableGCSKeyPrefix,
							},
							Credentials: kms.NewPlainSecret(portableGCSCredentials),
						},
						AzBlobConfig: vfs.AzBlobFsConfig{
							BaseAzBlobFsConfig: sdk.BaseAzBlobFsConfig{
								Container:           portableAzContainer,
								AccountName:         portableAzAccountName,
								Endpoint:            portableAzEndpoint,
								AccessTier:          portableAzAccessTier,
								KeyPrefix:           portableAzKeyPrefix,
								UseEmulator:         portableAzUseEmulator,
								UploadPartSize:      int64(portableAzULPartSize),
								UploadConcurrency:   portableAzULConcurrency,
								DownloadPartSize:    int64(portableAzDLPartSize),
								DownloadConcurrency: portableAzDLConcurrency,
							},
							AccountKey: kms.NewPlainSecret(portableAzAccountKey),
							SASURL:     kms.NewPlainSecret(portableAzSASURL),
						},
						CryptConfig: vfs.CryptFsConfig{
							Passphrase: kms.NewPlainSecret(portableCryptPassphrase),
						},
						SFTPConfig: vfs.SFTPFsConfig{
							BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
								Endpoint:                portableSFTPEndpoint,
								Username:                portableSFTPUsername,
								Fingerprints:            portableSFTPFingerprints,
								Prefix:                  portableSFTPPrefix,
								DisableCouncurrentReads: portableSFTPDisableConcurrentReads,
								BufferSize:              portableSFTPDBufferSize,
							},
							Password:   kms.NewPlainSecret(portableSFTPPassword),
							PrivateKey: kms.NewPlainSecret(portableSFTPPrivateKey),
						},
					},
				},
			}
			err := service.StartPortableMode(portableSFTPDPort, portableFTPDPort, portableWebDAVPort, portableHTTPPort,
				portableSSHCommands, portableFTPSCert, portableFTPSKey, portableWebDAVCert, portableWebDAVKey,
				portableHTTPSCert, portableHTTPSKey)
			if err == nil {
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
	portableCmd.Flags().StringVar(&portableStartDir, "start-directory", "/", `Alternate start directory.
This is a virtual path not a filesystem
path`)
	portableCmd.Flags().IntVarP(&portableSFTPDPort, "sftpd-port", "s", 0, `0 means a random unprivileged port,
< 0 disabled`)
	portableCmd.Flags().IntVar(&portableFTPDPort, "ftpd-port", -1, `0 means a random unprivileged port,
< 0 disabled`)
	portableCmd.Flags().IntVar(&portableWebDAVPort, "webdav-port", -1, `0 means a random unprivileged port,
< 0 disabled`)
	portableCmd.Flags().IntVar(&portableHTTPPort, "httpd-port", -1, `0 means a random unprivileged port,
< 0 disabled`)
	portableCmd.Flags().StringSliceVar(&portableSSHCommands, "ssh-commands", sftpd.GetDefaultSSHCommands(),
		`SSH commands to enable.
"*" means any supported SSH command
including scp
`)
	portableCmd.Flags().StringVarP(&portableUsername, "username", "u", "", `Leave empty to use an auto generated
value`)
	portableCmd.Flags().StringVarP(&portablePassword, "password", "p", "", `Leave empty to use an auto generated
value`)
	portableCmd.Flags().StringVar(&portablePasswordFile, "password-file", "", `Read the password from the specified
file path. Leave empty to use an auto
generated value`)
	portableCmd.Flags().StringVarP(&portableLogFile, logFilePathFlag, "l", "", "Leave empty to disable logging")
	portableCmd.Flags().StringVar(&portableLogLevel, logLevelFlag, defaultLogLevel, `Set the log level.
Supported values:

debug, info, warn, error.
`)
	portableCmd.Flags().BoolVar(&portableLogUTCTime, logUTCTimeFlag, false, "Use UTC time for logging")
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
	portableCmd.Flags().StringVarP(&portableFsProvider, "fs-provider", "f", "osfs", `osfs => local filesystem (legacy value: 0)
s3fs => AWS S3 compatible (legacy: 1)
gcsfs => Google Cloud Storage (legacy: 2)
azblobfs => Azure Blob Storage (legacy: 3)
cryptfs => Encrypted local filesystem (legacy: 4)
sftpfs => SFTP (legacy: 5)`)
	portableCmd.Flags().StringVar(&portableS3Bucket, "s3-bucket", "", "")
	portableCmd.Flags().StringVar(&portableS3Region, "s3-region", "", "")
	portableCmd.Flags().StringVar(&portableS3AccessKey, "s3-access-key", "", "")
	portableCmd.Flags().StringVar(&portableS3AccessSecret, "s3-access-secret", "", "")
	portableCmd.Flags().StringVar(&portableS3RoleARN, "s3-role-arn", "", "")
	portableCmd.Flags().StringVar(&portableS3Endpoint, "s3-endpoint", "", "")
	portableCmd.Flags().StringVar(&portableS3StorageClass, "s3-storage-class", "", "")
	portableCmd.Flags().StringVar(&portableS3ACL, "s3-acl", "", "")
	portableCmd.Flags().StringVar(&portableS3KeyPrefix, "s3-key-prefix", "", `Allows to restrict access to the
virtual folder identified by this
prefix and its contents`)
	portableCmd.Flags().IntVar(&portableS3ULPartSize, "s3-upload-part-size", 5, `The buffer size for multipart uploads
(MB)`)
	portableCmd.Flags().IntVar(&portableS3ULConcurrency, "s3-upload-concurrency", 2, `How many parts are uploaded in
parallel`)
	portableCmd.Flags().BoolVar(&portableS3ForcePathStyle, "s3-force-path-style", false, `Force path style bucket URL`)
	portableCmd.Flags().BoolVar(&portableS3SkipTLSVerify, "s3-skip-tls-verify", false, `If enabled the S3 client accepts any TLS
certificate presented by the server and
any host name in that certificate.
In this mode, TLS is susceptible to
man-in-the-middle attacks.
This should be used only for testing.
`)
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
	portableCmd.Flags().StringVar(&portableHTTPSCert, "httpd-cert", "", `Path to the certificate file for WebClient
over HTTPS`)
	portableCmd.Flags().StringVar(&portableHTTPSKey, "httpd-key", "", `Path to the key file for WebClient over
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
	portableCmd.Flags().IntVar(&portableAzULPartSize, "az-upload-part-size", 5, `The buffer size for multipart uploads
(MB)`)
	portableCmd.Flags().IntVar(&portableAzULConcurrency, "az-upload-concurrency", 5, `How many parts are uploaded in
parallel`)
	portableCmd.Flags().IntVar(&portableAzDLPartSize, "az-download-part-size", 5, `The buffer size for multipart downloads
(MB)`)
	portableCmd.Flags().IntVar(&portableAzDLConcurrency, "az-download-concurrency", 5, `How many parts are downloaded in
parallel`)
	portableCmd.Flags().BoolVar(&portableAzUseEmulator, "az-use-emulator", false, "")
	portableCmd.Flags().StringVar(&portableCryptPassphrase, "crypto-passphrase", "", `Passphrase for encryption/decryption`)
	portableCmd.Flags().StringVar(&portableSFTPEndpoint, "sftp-endpoint", "", `SFTP endpoint as host:port for SFTP
provider`)
	portableCmd.Flags().StringVar(&portableSFTPUsername, "sftp-username", "", `SFTP user for SFTP provider`)
	portableCmd.Flags().StringVar(&portableSFTPPassword, "sftp-password", "", `SFTP password for SFTP provider`)
	portableCmd.Flags().StringVar(&portableSFTPPrivateKeyPath, "sftp-key-path", "", `SFTP private key path for SFTP provider`)
	portableCmd.Flags().StringSliceVar(&portableSFTPFingerprints, "sftp-fingerprints", []string{}, `SFTP fingerprints to verify remote host
key for SFTP provider`)
	portableCmd.Flags().StringVar(&portableSFTPPrefix, "sftp-prefix", "", `SFTP prefix allows restrict all
operations to a given path within the
remote SFTP server`)
	portableCmd.Flags().BoolVar(&portableSFTPDisableConcurrentReads, "sftp-disable-concurrent-reads", false, `Concurrent reads are safe to use and
disabling them will degrade performance.
Disable for read once servers`)
	portableCmd.Flags().Int64Var(&portableSFTPDBufferSize, "sftp-buffer-size", 0, `The size of the buffer (in MB) to use
for transfers. By enabling buffering,
the reads and writes, from/to the
remote SFTP server, are split in
multiple concurrent requests and this
allows data to be transferred at a
faster rate, over high latency networks,
by overlapping round-trip times`)
	portableCmd.Flags().IntVar(&graceTime, graceTimeFlag, 0,
		`This grace time defines the number of
seconds allowed for existing transfers
to get completed before shutting down.
A graceful shutdown is triggered by an
interrupt signal.
`)
	addConfigFlags(portableCmd)
	rootCmd.AddCommand(portableCmd)
}

func parsePatternsFilesFilters() []sdk.PatternsFilter {
	var patterns []sdk.PatternsFilter
	for _, val := range portableAllowedPatterns {
		p, exts := getPatternsFilterValues(strings.TrimSpace(val))
		if p != "" {
			patterns = append(patterns, sdk.PatternsFilter{
				Path:            path.Clean(p),
				AllowedPatterns: exts,
				DeniedPatterns:  []string{},
			})
		}
	}
	for _, val := range portableDeniedPatterns {
		p, exts := getPatternsFilterValues(strings.TrimSpace(val))
		if p != "" {
			found := false
			for index, e := range patterns {
				if path.Clean(e.Path) == path.Clean(p) {
					patterns[index].DeniedPatterns = append(patterns[index].DeniedPatterns, exts...)
					found = true
					break
				}
			}
			if !found {
				patterns = append(patterns, sdk.PatternsFilter{
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
				if cleanedExt != "" {
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

func getFileContents(name string) (string, error) {
	fi, err := os.Stat(name)
	if err != nil {
		return "", err
	}
	if fi.Size() > 1048576 {
		return "", fmt.Errorf("%q is too big %v/1048576 bytes", name, fi.Size())
	}
	contents, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(contents), nil
}
