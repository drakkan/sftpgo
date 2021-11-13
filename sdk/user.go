package sdk

import (
	"strings"

	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/util"
)

// Web Client/user REST API restrictions
const (
	WebClientPubKeyChangeDisabled     = "publickey-change-disabled"
	WebClientWriteDisabled            = "write-disabled"
	WebClientMFADisabled              = "mfa-disabled"
	WebClientPasswordChangeDisabled   = "password-change-disabled"
	WebClientAPIKeyAuthChangeDisabled = "api-key-auth-change-disabled"
	WebClientInfoChangeDisabled       = "info-change-disabled"
	WebClientSharesDisabled           = "shares-disabled"
	WebClientPasswordResetDisabled    = "password-reset-disabled"
)

var (
	// WebClientOptions defines the available options for the web client interface/user REST API
	WebClientOptions = []string{WebClientWriteDisabled, WebClientPasswordChangeDisabled, WebClientPasswordResetDisabled,
		WebClientPubKeyChangeDisabled, WebClientMFADisabled, WebClientAPIKeyAuthChangeDisabled, WebClientInfoChangeDisabled,
		WebClientSharesDisabled}
	// UserTypes defines the supported user type hints for auth plugins
	UserTypes = []string{string(UserTypeLDAP), string(UserTypeOS)}
)

// TLSUsername defines the TLS certificate attribute to use as username
type TLSUsername string

// Supported certificate attributes to use as username
const (
	TLSUsernameNone TLSUsername = "None"
	TLSUsernameCN   TLSUsername = "CommonName"
)

// UserType defines the supported user types.
// This is an hint for external auth plugins, is not used in SFTPGo directly
type UserType string

// User types, auth plugins could use this info to choose the correct authentication backend
const (
	UserTypeLDAP UserType = "LDAPUser"
	UserTypeOS   UserType = "OSUser"
)

// DirectoryPermissions defines permissions for a directory virtual path
type DirectoryPermissions struct {
	Path        string
	Permissions []string
}

// HasPerm returns true if the directory has the specified permissions
func (d *DirectoryPermissions) HasPerm(perm string) bool {
	return util.IsStringInSlice(perm, d.Permissions)
}

// PatternsFilter defines filters based on shell like patterns.
// These restrictions do not apply to files listing for performance reasons, so
// a denied file cannot be downloaded/overwritten/renamed but will still be
// in the list of files.
// System commands such as Git and rsync interacts with the filesystem directly
// and they are not aware about these restrictions so they are not allowed
// inside paths with extensions filters
type PatternsFilter struct {
	// Virtual path, if no other specific filter is defined, the filter applies for
	// sub directories too.
	// For example if filters are defined for the paths "/" and "/sub" then the
	// filters for "/" are applied for any file outside the "/sub" directory
	Path string `json:"path"`
	// files with these, case insensitive, patterns are allowed.
	// Denied file patterns are evaluated before the allowed ones
	AllowedPatterns []string `json:"allowed_patterns,omitempty"`
	// files with these, case insensitive, patterns are not allowed.
	// Denied file patterns are evaluated before the allowed ones
	DeniedPatterns []string `json:"denied_patterns,omitempty"`
}

// GetCommaSeparatedPatterns returns the first non empty patterns list comma separated
func (p *PatternsFilter) GetCommaSeparatedPatterns() string {
	if len(p.DeniedPatterns) > 0 {
		return strings.Join(p.DeniedPatterns, ",")
	}
	return strings.Join(p.AllowedPatterns, ",")
}

// IsDenied returns true if the patterns has one or more denied patterns
func (p *PatternsFilter) IsDenied() bool {
	return len(p.DeniedPatterns) > 0
}

// IsAllowed returns true if the patterns has one or more allowed patterns
func (p *PatternsFilter) IsAllowed() bool {
	return len(p.AllowedPatterns) > 0
}

// HooksFilter defines user specific overrides for global hooks
type HooksFilter struct {
	ExternalAuthDisabled  bool `json:"external_auth_disabled"`
	PreLoginDisabled      bool `json:"pre_login_disabled"`
	CheckPasswordDisabled bool `json:"check_password_disabled"`
}

// RecoveryCode defines a 2FA recovery code
type RecoveryCode struct {
	Secret *kms.Secret `json:"secret"`
	Used   bool        `json:"used,omitempty"`
}

// TOTPConfig defines the time-based one time password configuration
type TOTPConfig struct {
	Enabled    bool        `json:"enabled,omitempty"`
	ConfigName string      `json:"config_name,omitempty"`
	Secret     *kms.Secret `json:"secret,omitempty"`
	// TOTP will be required for the specified protocols.
	// SSH protocol (SFTP/SCP/SSH commands) will ask for the TOTP passcode if the client uses keyboard interactive
	// authentication.
	// FTP have no standard way to support two factor authentication, if you
	// enable the support for this protocol you have to add the TOTP passcode after the password.
	// For example if your password is "password" and your one time passcode is
	// "123456" you have to use "password123456" as password.
	Protocols []string `json:"protocols,omitempty"`
}

// UserFilters defines additional restrictions for a user
// TODO: rename to UserOptions in v3
type UserFilters struct {
	// only clients connecting from these IP/Mask are allowed.
	// IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291
	// for example "192.0.2.0/24" or "2001:db8::/32"
	AllowedIP []string `json:"allowed_ip,omitempty"`
	// clients connecting from these IP/Mask are not allowed.
	// Denied rules will be evaluated before allowed ones
	DeniedIP []string `json:"denied_ip,omitempty"`
	// these login methods are not allowed.
	// If null or empty any available login method is allowed
	DeniedLoginMethods []string `json:"denied_login_methods,omitempty"`
	// these protocols are not allowed.
	// If null or empty any available protocol is allowed
	DeniedProtocols []string `json:"denied_protocols,omitempty"`
	// filter based on shell patterns.
	// Please note that these restrictions can be easily bypassed.
	FilePatterns []PatternsFilter `json:"file_patterns,omitempty"`
	// max size allowed for a single upload, 0 means unlimited
	MaxUploadFileSize int64 `json:"max_upload_file_size,omitempty"`
	// TLS certificate attribute to use as username.
	// For FTP clients it must match the name provided using the
	// "USER" command
	TLSUsername TLSUsername `json:"tls_username,omitempty"`
	// user specific hook overrides
	Hooks HooksFilter `json:"hooks,omitempty"`
	// Disable checks for existence and automatic creation of home directory
	// and virtual folders.
	// SFTPGo requires that the user's home directory, virtual folder root,
	// and intermediate paths to virtual folders exist to work properly.
	// If you already know that the required directories exist, disabling
	// these checks will speed up login.
	// You could, for example, disable these checks after the first login
	DisableFsChecks bool `json:"disable_fs_checks,omitempty"`
	// WebClient related configuration options
	WebClient []string `json:"web_client,omitempty"`
	// API key auth allows to impersonate this user with an API key
	AllowAPIKeyAuth bool `json:"allow_api_key_auth,omitempty"`
	// Time-based one time passwords configuration
	TOTPConfig TOTPConfig `json:"totp_config,omitempty"`
	// Recovery codes to use if the user loses access to their second factor auth device.
	// Each code can only be used once, you should use these codes to login and disable or
	// reset 2FA for your account
	RecoveryCodes []RecoveryCode `json:"recovery_codes,omitempty"`
	// UserType is an hint for authentication plugins.
	// It is ignored when using SFTPGo internal authentication
	UserType string `json:"user_type,omitempty"`
}

type BaseUser struct {
	// Data provider unique identifier
	ID int64 `json:"id"`
	// 1 enabled, 0 disabled (login is not allowed)
	Status int `json:"status"`
	// Username
	Username string `json:"username"`
	// Email
	Email string `json:"email,omitempty"`
	// Account expiration date as unix timestamp in milliseconds. An expired account cannot login.
	// 0 means no expiration
	ExpirationDate int64 `json:"expiration_date"`
	// Password used for password authentication.
	// For users created using SFTPGo REST API the password is be stored using bcrypt or argon2id hashing algo.
	// Checking passwords stored with pbkdf2, md5crypt and sha512crypt is supported too.
	Password string `json:"password,omitempty"`
	// PublicKeys used for public key authentication. At least one between password and a public key is mandatory
	PublicKeys []string `json:"public_keys,omitempty"`
	// The user cannot upload or download files outside this directory. Must be an absolute path
	HomeDir string `json:"home_dir"`
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
	// Creation time as unix timestamp in milliseconds. It will be 0 for admins created before v2.2.0
	CreatedAt int64 `json:"created_at"`
	// last update time as unix timestamp in milliseconds
	UpdatedAt int64 `json:"updated_at"`
	// Additional restrictions
	Filters UserFilters `json:"filters"`
	// optional description, for example full name
	Description string `json:"description,omitempty"`
	// free form text field for external systems
	AdditionalInfo string `json:"additional_info,omitempty"`
}

// User defines a SFTPGo user
type User struct {
	BaseUser
	// Mapping between virtual paths and virtual folders
	VirtualFolders []VirtualFolder `json:"virtual_folders,omitempty"`
	// Filesystem configuration details
	FsConfig Filesystem `json:"filesystem"`
}
