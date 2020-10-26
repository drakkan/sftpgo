package httpd

type apiResponse struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"status"`
}

type externalAuthRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	PublicKey string `json:"public_key"`
}

// SFTPGoExtensionsFilter defines filters based on file extensions
type SFTPGoExtensionsFilter struct {
	Path              string   `json:"path"`
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
	DeniedExtensions  []string `json:"denied_extensions,omitempty"`
}

// SFTPGoUserFilters defines additional restrictions for an SFTPGo user
type SFTPGoUserFilters struct {
	AllowedIP          []string                 `json:"allowed_ip,omitempty"`
	DeniedIP           []string                 `json:"denied_ip,omitempty"`
	DeniedLoginMethods []string                 `json:"denied_login_methods,omitempty"`
	FileExtensions     []SFTPGoExtensionsFilter `json:"file_extensions,omitempty"`
}

// S3FsConfig defines the configuration for S3 based filesystem
type S3FsConfig struct {
	Bucket            string `json:"bucket,omitempty"`
	KeyPrefix         string `json:"key_prefix,omitempty"`
	Region            string `json:"region,omitempty"`
	AccessKey         string `json:"access_key,omitempty"`
	AccessSecret      string `json:"access_secret,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
	StorageClass      string `json:"storage_class,omitempty"`
	UploadPartSize    int64  `json:"upload_part_size,omitempty"`
	UploadConcurrency int    `json:"upload_concurrency,omitempty"`
}

// GCSFsConfig defines the configuration for Google Cloud Storage based filesystem
type GCSFsConfig struct {
	Bucket               string `json:"bucket,omitempty"`
	KeyPrefix            string `json:"key_prefix,omitempty"`
	Credentials          string `json:"credentials,omitempty"`
	AutomaticCredentials int    `json:"automatic_credentials,omitempty"`
	StorageClass         string `json:"storage_class,omitempty"`
}

// SFTPGoFilesystem defines cloud storage filesystem details
type SFTPGoFilesystem struct {
	// 0 local filesystem, 1 AWS S3 compatible, 2 Google Cloud Storage
	Provider  int         `json:"provider"`
	S3Config  S3FsConfig  `json:"s3config,omitempty"`
	GCSConfig GCSFsConfig `json:"gcsconfig,omitempty"`
}

type virtualFolder struct {
	VirtualPath string `json:"virtual_path"`
	MappedPath  string `json:"mapped_path"`
}

// SFTPGoUser defines an SFTPGo user
type SFTPGoUser struct {
	// Database unique identifier
	ID int64 `json:"id"`
	// 1 enabled, 0 disabled (login is not allowed)
	Status int `json:"status"`
	// Username
	Username string `json:"username"`
	// Account expiration date as unix timestamp in milliseconds. An expired account cannot login.
	// 0 means no expiration
	ExpirationDate int64    `json:"expiration_date"`
	Password       string   `json:"password,omitempty"`
	PublicKeys     []string `json:"public_keys,omitempty"`
	HomeDir        string   `json:"home_dir"`
	// Mapping between virtual paths and filesystem paths outside the home directory. Supported for local filesystem only
	VirtualFolders []virtualFolder `json:"virtual_folders,omitempty"`
	// If sftpgo runs as root system user then the created files and directories will be assigned to this system UID
	UID int `json:"uid"`
	// If sftpgo runs as root system user then the created files and directories will be assigned to this system GID
	GID int `json:"gid"`
	// Maximum concurrent sessions. 0 means unlimited
	MaxSessions int `json:"max_sessions"`
	// Maximum size allowed as bytes. 0 means unlimited
	QuotaSize int64 `json:"quota_size"`
	// Maximum number of files allowed. 0 means unlimited
	QuotaFiles int `json:"quota_files"`
	// List of the granted permissions
	Permissions map[string][]string `json:"permissions"`
	// Used quota as bytes
	UsedQuotaSize int64 `json:"used_quota_size"`
	// Used quota as number of files
	UsedQuotaFiles int `json:"used_quota_files"`
	// Last quota update as unix timestamp in milliseconds
	LastQuotaUpdate int64 `json:"last_quota_update"`
	// Maximum upload bandwidth as KB/s, 0 means unlimited
	UploadBandwidth int64 `json:"upload_bandwidth"`
	// Maximum download bandwidth as KB/s, 0 means unlimited
	DownloadBandwidth int64 `json:"download_bandwidth"`
	// Last login as unix timestamp in milliseconds
	LastLogin int64 `json:"last_login"`
	// Additional restrictions
	Filters SFTPGoUserFilters `json:"filters"`
	// Filesystem configuration details
	FsConfig SFTPGoFilesystem `json:"filesystem"`
}
