package sdk

import "github.com/drakkan/sftpgo/v2/kms"

// FilesystemProvider defines the supported storage filesystems
type FilesystemProvider int

// supported values for FilesystemProvider
const (
	LocalFilesystemProvider     FilesystemProvider = iota // Local
	S3FilesystemProvider                                  // AWS S3 compatible
	GCSFilesystemProvider                                 // Google Cloud Storage
	AzureBlobFilesystemProvider                           // Azure Blob Storage
	CryptedFilesystemProvider                             // Local encrypted
	SFTPFilesystemProvider                                // SFTP
)

// GetProviderByName returns the FilesystemProvider matching a given name
// to provide backwards compatibility, numeric strings are accepted as well
func GetProviderByName(name string) FilesystemProvider {
	switch name {
	case "0", "osfs":
		return LocalFilesystemProvider
	case "1", "s3fs":
		return S3FilesystemProvider
	case "2", "gcsfs":
		return GCSFilesystemProvider
	case "3", "azblobfs":
		return AzureBlobFilesystemProvider
	case "4", "cryptfs":
		return CryptedFilesystemProvider
	case "5", "sftpfs":
		return SFTPFilesystemProvider
	}

	// TODO think about returning an error value instead of silently defaulting to LocalFilesystemProvider
	return LocalFilesystemProvider
}

// Name returns the Provider's unique name
func (p FilesystemProvider) Name() string {
	switch p {
	case LocalFilesystemProvider:
		return "osfs"
	case S3FilesystemProvider:
		return "s3fs"
	case GCSFilesystemProvider:
		return "gcsfs"
	case AzureBlobFilesystemProvider:
		return "azblobfs"
	case CryptedFilesystemProvider:
		return "cryptfs"
	case SFTPFilesystemProvider:
		return "sftpfs"
	}
	return "" // let's not claim to be
}

// ShortInfo returns a human readable, short description for the given FilesystemProvider
func (p FilesystemProvider) ShortInfo() string {
	switch p {
	case LocalFilesystemProvider:
		return "Local"
	case S3FilesystemProvider:
		return "AWS S3 (Compatible)"
	case GCSFilesystemProvider:
		return "Google Cloud Storage"
	case AzureBlobFilesystemProvider:
		return "Azure Blob Storage"
	case CryptedFilesystemProvider:
		return "Local encrypted"
	case SFTPFilesystemProvider:
		return "SFTP"
	}
	return ""
}

// ListProviders returns a list of available FilesystemProviders.
func ListProviders() []FilesystemProvider {
	return []FilesystemProvider{
		LocalFilesystemProvider, S3FilesystemProvider,
		GCSFilesystemProvider, AzureBlobFilesystemProvider,
		CryptedFilesystemProvider, SFTPFilesystemProvider,
	}
}

// S3FsConfig defines the configuration for S3 based filesystem
type S3FsConfig struct {
	Bucket string `json:"bucket,omitempty"`
	// KeyPrefix is similar to a chroot directory for local filesystem.
	// If specified then the SFTP user will only see objects that starts
	// with this prefix and so you can restrict access to a specific
	// folder. The prefix, if not empty, must not start with "/" and must
	// end with "/".
	// If empty the whole bucket contents will be available
	KeyPrefix    string      `json:"key_prefix,omitempty"`
	Region       string      `json:"region,omitempty"`
	AccessKey    string      `json:"access_key,omitempty"`
	AccessSecret *kms.Secret `json:"access_secret,omitempty"`
	Endpoint     string      `json:"endpoint,omitempty"`
	StorageClass string      `json:"storage_class,omitempty"`
	// The canned ACL to apply to uploaded objects. Leave empty to use the default ACL.
	// For more information and available ACLs, see here:
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#canned-acl
	ACL string `json:"acl,omitempty"`
	// The buffer size (in MB) to use for multipart uploads. The minimum allowed part size is 5MB,
	// and if this value is set to zero, the default value (5MB) for the AWS SDK will be used.
	// The minimum allowed value is 5.
	// Please note that if the upload bandwidth between the SFTP client and SFTPGo is greater than
	// the upload bandwidth between SFTPGo and S3 then the SFTP client have to wait for the upload
	// of the last parts to S3 after it ends the file upload to SFTPGo, and it may time out.
	// Keep this in mind if you customize these parameters.
	UploadPartSize int64 `json:"upload_part_size,omitempty"`
	// How many parts are uploaded in parallel
	UploadConcurrency int `json:"upload_concurrency,omitempty"`
	// The buffer size (in MB) to use for multipart downloads. The minimum allowed part size is 5MB,
	// and if this value is set to zero, the default value (5MB) for the AWS SDK will be used.
	// The minimum allowed value is 5. Ignored for partial downloads.
	DownloadPartSize int64 `json:"download_part_size,omitempty"`
	// How many parts are downloaded in parallel. Ignored for partial downloads.
	DownloadConcurrency int `json:"download_concurrency,omitempty"`
	// DownloadPartMaxTime defines the maximum time allowed, in seconds, to download a single chunk (5MB).
	// 0 means no timeout. Ignored for partial downloads.
	DownloadPartMaxTime int `json:"download_part_max_time,omitempty"`
	// Set this to `true` to force the request to use path-style addressing,
	// i.e., `http://s3.amazonaws.com/BUCKET/KEY`. By default, the S3 client
	// will use virtual hosted bucket addressing when possible
	// (`http://BUCKET.s3.amazonaws.com/KEY`)
	ForcePathStyle bool `json:"force_path_style,omitempty"`
}

// GCSFsConfig defines the configuration for Google Cloud Storage based filesystem
type GCSFsConfig struct {
	Bucket string `json:"bucket,omitempty"`
	// KeyPrefix is similar to a chroot directory for local filesystem.
	// If specified then the SFTP user will only see objects that starts
	// with this prefix and so you can restrict access to a specific
	// folder. The prefix, if not empty, must not start with "/" and must
	// end with "/".
	// If empty the whole bucket contents will be available
	KeyPrefix      string      `json:"key_prefix,omitempty"`
	CredentialFile string      `json:"-"`
	Credentials    *kms.Secret `json:"credentials,omitempty"`
	// 0 explicit, 1 automatic
	AutomaticCredentials int    `json:"automatic_credentials,omitempty"`
	StorageClass         string `json:"storage_class,omitempty"`
	// The ACL to apply to uploaded objects. Leave empty to use the default ACL.
	// For more information and available ACLs, refer to the JSON API here:
	// https://cloud.google.com/storage/docs/access-control/lists#predefined-acl
	ACL string `json:"acl,omitempty"`
}

// AzBlobFsConfig defines the configuration for Azure Blob Storage based filesystem
type AzBlobFsConfig struct {
	Container string `json:"container,omitempty"`
	// Storage Account Name, leave blank to use SAS URL
	AccountName string `json:"account_name,omitempty"`
	// Storage Account Key leave blank to use SAS URL.
	// The access key is stored encrypted based on the kms configuration
	AccountKey *kms.Secret `json:"account_key,omitempty"`
	// Optional endpoint. Default is "blob.core.windows.net".
	// If you use the emulator the endpoint must include the protocol,
	// for example "http://127.0.0.1:10000"
	Endpoint string `json:"endpoint,omitempty"`
	// Shared access signature URL, leave blank if using account/key
	SASURL *kms.Secret `json:"sas_url,omitempty"`
	// KeyPrefix is similar to a chroot directory for local filesystem.
	// If specified then the SFTPGo user will only see objects that starts
	// with this prefix and so you can restrict access to a specific
	// folder. The prefix, if not empty, must not start with "/" and must
	// end with "/".
	// If empty the whole bucket contents will be available
	KeyPrefix string `json:"key_prefix,omitempty"`
	// The buffer size (in MB) to use for multipart uploads.
	// If this value is set to zero, the default value (1MB) for the Azure SDK will be used.
	// Please note that if the upload bandwidth between the SFTPGo client and SFTPGo server is
	// greater than the upload bandwidth between SFTPGo and Azure then the SFTP client have
	// to wait for the upload of the last parts to Azure after it ends the file upload to SFTPGo,
	// and it may time out.
	// Keep this in mind if you customize these parameters.
	UploadPartSize int64 `json:"upload_part_size,omitempty"`
	// How many parts are uploaded in parallel
	UploadConcurrency int `json:"upload_concurrency,omitempty"`
	// Set to true if you use an Azure emulator such as Azurite
	UseEmulator bool `json:"use_emulator,omitempty"`
	// Blob Access Tier
	AccessTier string `json:"access_tier,omitempty"`
}

// CryptFsConfig defines the configuration to store local files as encrypted
type CryptFsConfig struct {
	Passphrase *kms.Secret `json:"passphrase,omitempty"`
}

// SFTPFsConfig defines the configuration for SFTP based filesystem
type SFTPFsConfig struct {
	Endpoint     string      `json:"endpoint,omitempty"`
	Username     string      `json:"username,omitempty"`
	Password     *kms.Secret `json:"password,omitempty"`
	PrivateKey   *kms.Secret `json:"private_key,omitempty"`
	Fingerprints []string    `json:"fingerprints,omitempty"`
	// Prefix is the path prefix to strip from SFTP resource paths.
	Prefix string `json:"prefix,omitempty"`
	// Concurrent reads are safe to use and disabling them will degrade performance.
	// Some servers automatically delete files once they are downloaded.
	// Using concurrent reads is problematic with such servers.
	DisableCouncurrentReads bool `json:"disable_concurrent_reads,omitempty"`
	// The buffer size (in MB) to use for transfers.
	// Buffering could improve performance for high latency networks.
	// With buffering enabled upload resume is not supported and a file
	// cannot be opened for both reading and writing at the same time
	// 0 means disabled.
	BufferSize int64 `json:"buffer_size,omitempty"`
}

// Filesystem defines filesystem details
type Filesystem struct {
	Provider     FilesystemProvider `json:"provider"`
	S3Config     S3FsConfig         `json:"s3config,omitempty"`
	GCSConfig    GCSFsConfig        `json:"gcsconfig,omitempty"`
	AzBlobConfig AzBlobFsConfig     `json:"azblobconfig,omitempty"`
	CryptConfig  CryptFsConfig      `json:"cryptconfig,omitempty"`
	SFTPConfig   SFTPFsConfig       `json:"sftpconfig,omitempty"`
}
