package dataprovider

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"

	"github.com/drakkan/sftpgo/utils"
)

// Available permissions for SFTPGo admins
const (
	PermAdminAny              = "*"
	PermAdminAddUsers         = "add_users"
	PermAdminChangeUsers      = "edit_users"
	PermAdminDeleteUsers      = "del_users"
	PermAdminViewUsers        = "view_users"
	PermAdminViewConnections  = "view_conns"
	PermAdminCloseConnections = "close_conns"
	PermAdminViewServerStatus = "view_status"
	PermAdminManageAdmins     = "manage_admins"
	PermAdminQuotaScans       = "quota_scans"
	PermAdminManageSystem     = "manage_system"
	PermAdminManageDefender   = "manage_defender"
	PermAdminViewDefender     = "view_defender"
)

var (
	emailRegex      = regexp.MustCompile("^(?:(?:(?:(?:[a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(?:\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|(?:(?:\\x22)(?:(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(?:\\x20|\\x09)+)?(?:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(\\x20|\\x09)+)?(?:\\x22))))@(?:(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
	validAdminPerms = []string{PermAdminAny, PermAdminAddUsers, PermAdminChangeUsers, PermAdminDeleteUsers,
		PermAdminViewUsers, PermAdminViewConnections, PermAdminCloseConnections, PermAdminViewServerStatus,
		PermAdminManageAdmins, PermAdminQuotaScans, PermAdminManageSystem, PermAdminManageDefender,
		PermAdminViewDefender}
)

// AdminFilters defines additional restrictions for SFTPGo admins
// TODO: rename to AdminOptions in v3
type AdminFilters struct {
	// only clients connecting from these IP/Mask are allowed.
	// IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291
	// for example "192.0.2.0/24" or "2001:db8::/32"
	AllowList []string `json:"allow_list,omitempty"`
}

// Admin defines a SFTPGo admin
type Admin struct {
	// Database unique identifier
	ID int64 `json:"id"`
	// 1 enabled, 0 disabled (login is not allowed)
	Status int `json:"status"`
	// Username
	Username       string       `json:"username"`
	Password       string       `json:"password,omitempty"`
	Email          string       `json:"email"`
	Permissions    []string     `json:"permissions"`
	Filters        AdminFilters `json:"filters,omitempty"`
	Description    string       `json:"description,omitempty"`
	AdditionalInfo string       `json:"additional_info,omitempty"`
}

func (a *Admin) checkPassword() error {
	if a.Password != "" && !utils.IsStringPrefixInSlice(a.Password, internalHashPwdPrefixes) {
		if config.PasswordHashing.Algo == HashingAlgoBcrypt {
			pwd, err := bcrypt.GenerateFromPassword([]byte(a.Password), config.PasswordHashing.BcryptOptions.Cost)
			if err != nil {
				return err
			}
			a.Password = string(pwd)
		} else {
			pwd, err := argon2id.CreateHash(a.Password, argon2Params)
			if err != nil {
				return err
			}
			a.Password = pwd
		}
	}
	return nil
}

func (a *Admin) validate() error {
	if a.Username == "" {
		return &ValidationError{err: "username is mandatory"}
	}
	if a.Password == "" {
		return &ValidationError{err: "please set a password"}
	}
	if !config.SkipNaturalKeysValidation && !usernameRegex.MatchString(a.Username) {
		return &ValidationError{err: fmt.Sprintf("username %#v is not valid, the following characters are allowed: a-zA-Z0-9-_.~", a.Username)}
	}
	if err := a.checkPassword(); err != nil {
		return err
	}
	a.Permissions = utils.RemoveDuplicates(a.Permissions)
	if len(a.Permissions) == 0 {
		return &ValidationError{err: "please grant some permissions to this admin"}
	}
	if utils.IsStringInSlice(PermAdminAny, a.Permissions) {
		a.Permissions = []string{PermAdminAny}
	}
	for _, perm := range a.Permissions {
		if !utils.IsStringInSlice(perm, validAdminPerms) {
			return &ValidationError{err: fmt.Sprintf("invalid permission: %#v", perm)}
		}
	}
	if a.Email != "" && !emailRegex.MatchString(a.Email) {
		return &ValidationError{err: fmt.Sprintf("email %#v is not valid", a.Email)}
	}
	for _, IPMask := range a.Filters.AllowList {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return &ValidationError{err: fmt.Sprintf("could not parse allow list entry %#v : %v", IPMask, err)}
		}
	}

	return nil
}

// CheckPassword verifies the admin password
func (a *Admin) CheckPassword(password string) (bool, error) {
	if strings.HasPrefix(a.Password, bcryptPwdPrefix) {
		if err := bcrypt.CompareHashAndPassword([]byte(a.Password), []byte(password)); err != nil {
			return false, ErrInvalidCredentials
		}
		return true, nil
	}
	return argon2id.ComparePasswordAndHash(password, a.Password)
}

// CanLoginFromIP returns true if login from the given IP is allowed
func (a *Admin) CanLoginFromIP(ip string) bool {
	if len(a.Filters.AllowList) == 0 {
		return true
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return len(a.Filters.AllowList) == 0
	}

	for _, ipMask := range a.Filters.AllowList {
		_, network, err := net.ParseCIDR(ipMask)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func (a *Admin) checkUserAndPass(password, ip string) error {
	if a.Status != 1 {
		return fmt.Errorf("admin %#v is disabled", a.Username)
	}
	if a.Password == "" || password == "" {
		return errors.New("credentials cannot be null or empty")
	}
	match, err := a.CheckPassword(password)
	if err != nil {
		return err
	}
	if !match {
		return ErrInvalidCredentials
	}
	if !a.CanLoginFromIP(ip) {
		return fmt.Errorf("login from IP %v not allowed", ip)
	}
	return nil
}

// HideConfidentialData hides admin confidential data
func (a *Admin) HideConfidentialData() {
	a.Password = ""
}

// HasPermission returns true if the admin has the specified permission
func (a *Admin) HasPermission(perm string) bool {
	if utils.IsStringInSlice(PermAdminAny, a.Permissions) {
		return true
	}
	return utils.IsStringInSlice(perm, a.Permissions)
}

// GetPermissionsAsString returns permission as string
func (a *Admin) GetPermissionsAsString() string {
	return strings.Join(a.Permissions, ", ")
}

// GetAllowedIPAsString returns the allowed IP as comma separated string
func (a *Admin) GetAllowedIPAsString() string {
	return strings.Join(a.Filters.AllowList, ",")
}

// GetValidPerms returns the allowed admin permissions
func (a *Admin) GetValidPerms() []string {
	return validAdminPerms
}

// GetInfoString returns admin's info as string.
func (a *Admin) GetInfoString() string {
	var result string
	if a.Email != "" {
		result = fmt.Sprintf("Email: %v. ", a.Email)
	}
	if len(a.Filters.AllowList) > 0 {
		result += fmt.Sprintf("Allowed IP/Mask: %v. ", len(a.Filters.AllowList))
	}
	return result
}

// GetSignature returns a signature for this admin.
// It could change after an update
func (a *Admin) GetSignature() string {
	data := []byte(a.Username)
	data = append(data, []byte(a.Password)...)
	signature := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(signature[:])
}

func (a *Admin) getACopy() Admin {
	permissions := make([]string, len(a.Permissions))
	copy(permissions, a.Permissions)
	filters := AdminFilters{}
	filters.AllowList = make([]string, len(a.Filters.AllowList))
	copy(filters.AllowList, a.Filters.AllowList)

	return Admin{
		ID:             a.ID,
		Status:         a.Status,
		Username:       a.Username,
		Password:       a.Password,
		Email:          a.Email,
		Permissions:    permissions,
		Filters:        filters,
		AdditionalInfo: a.AdditionalInfo,
		Description:    a.Description,
	}
}

// setDefaults sets the appropriate value for the default admin
func (a *Admin) setDefaults() {
	a.Username = "admin"
	a.Password = "password"
	a.Status = 1
	a.Permissions = []string{PermAdminAny}
}
