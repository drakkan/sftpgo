package sdk

// BaseVirtualFolder defines the path for the virtual folder and the used quota limits.
// The same folder can be shared among multiple users and each user can have different
// quota limits or a different virtual path.
type BaseVirtualFolder struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	MappedPath    string `json:"mapped_path,omitempty"`
	Description   string `json:"description,omitempty"`
	UsedQuotaSize int64  `json:"used_quota_size"`
	// Used quota as number of files
	UsedQuotaFiles int `json:"used_quota_files"`
	// Last quota update as unix timestamp in milliseconds
	LastQuotaUpdate int64 `json:"last_quota_update"`
	// list of usernames associated with this virtual folder
	Users []string `json:"users,omitempty"`
	// Filesystem configuration details
	FsConfig Filesystem `json:"filesystem"`
}

// VirtualFolder defines a mapping between an SFTPGo exposed virtual path and a
// filesystem path outside the user home directory.
// The specified paths must be absolute and the virtual path cannot be "/",
// it must be a sub directory. The parent directory for the specified virtual
// path must exist. SFTPGo will, by default, try to automatically create any missing
// parent directory for the configured virtual folders at user login.
type VirtualFolder struct {
	BaseVirtualFolder
	VirtualPath string `json:"virtual_path"`
	// Maximum size allowed as bytes. 0 means unlimited, -1 included in user quota
	QuotaSize int64 `json:"quota_size"`
	// Maximum number of files allowed. 0 means unlimited, -1 included in user quota
	QuotaFiles int `json:"quota_files"`
}
