// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dataprovider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/alexedwards/argon2id"
	"github.com/sftpgo/sdk"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/util"
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
	PermAdminManageGroups     = "manage_groups"
	PermAdminManageAPIKeys    = "manage_apikeys"
	PermAdminQuotaScans       = "quota_scans"
	PermAdminManageSystem     = "manage_system"
	PermAdminManageDefender   = "manage_defender"
	PermAdminViewDefender     = "view_defender"
	PermAdminRetentionChecks  = "retention_checks"
	PermAdminMetadataChecks   = "metadata_checks"
	PermAdminViewEvents       = "view_events"
	PermAdminManageEventRules = "manage_event_rules"
)

const (
	// GroupAddToUsersAsMembership defines that the admin's group will be added as membership group for new users
	GroupAddToUsersAsMembership = iota
	// GroupAddToUsersAsPrimary defines that the admin's group will be added as primary group for new users
	GroupAddToUsersAsPrimary
	// GroupAddToUsersAsSecondary defines that the admin's group will be added as secondary group for new users
	GroupAddToUsersAsSecondary
)

var (
	validAdminPerms = []string{PermAdminAny, PermAdminAddUsers, PermAdminChangeUsers, PermAdminDeleteUsers,
		PermAdminViewUsers, PermAdminManageGroups, PermAdminViewConnections, PermAdminCloseConnections,
		PermAdminViewServerStatus, PermAdminManageAdmins, PermAdminManageAPIKeys, PermAdminQuotaScans,
		PermAdminManageSystem, PermAdminManageDefender, PermAdminViewDefender, PermAdminRetentionChecks,
		PermAdminMetadataChecks, PermAdminViewEvents}
)

// AdminTOTPConfig defines the time-based one time password configuration
type AdminTOTPConfig struct {
	Enabled    bool        `json:"enabled,omitempty"`
	ConfigName string      `json:"config_name,omitempty"`
	Secret     *kms.Secret `json:"secret,omitempty"`
}

func (c *AdminTOTPConfig) validate(username string) error {
	if !c.Enabled {
		c.ConfigName = ""
		c.Secret = kms.NewEmptySecret()
		return nil
	}
	if c.ConfigName == "" {
		return util.NewValidationError("totp: config name is mandatory")
	}
	if !util.Contains(mfa.GetAvailableTOTPConfigNames(), c.ConfigName) {
		return util.NewValidationError(fmt.Sprintf("totp: config name %#v not found", c.ConfigName))
	}
	if c.Secret.IsEmpty() {
		return util.NewValidationError("totp: secret is mandatory")
	}
	if c.Secret.IsPlain() {
		c.Secret.SetAdditionalData(username)
		if err := c.Secret.Encrypt(); err != nil {
			return util.NewValidationError(fmt.Sprintf("totp: unable to encrypt secret: %v", err))
		}
	}
	return nil
}

// AdminFilters defines additional restrictions for SFTPGo admins
// TODO: rename to AdminOptions in v3
type AdminFilters struct {
	// only clients connecting from these IP/Mask are allowed.
	// IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291
	// for example "192.0.2.0/24" or "2001:db8::/32"
	AllowList []string `json:"allow_list,omitempty"`
	// API key auth allows to impersonate this administrator with an API key
	AllowAPIKeyAuth bool `json:"allow_api_key_auth,omitempty"`
	// Time-based one time passwords configuration
	TOTPConfig AdminTOTPConfig `json:"totp_config,omitempty"`
	// Recovery codes to use if the user loses access to their second factor auth device.
	// Each code can only be used once, you should use these codes to login and disable or
	// reset 2FA for your account
	RecoveryCodes []RecoveryCode `json:"recovery_codes,omitempty"`
}

// AdminGroupMappingOptions defines the options for admin/group mapping
type AdminGroupMappingOptions struct {
	AddToUsersAs int `json:"add_to_users_as,omitempty"`
}

func (o *AdminGroupMappingOptions) validate() error {
	if o.AddToUsersAs < GroupAddToUsersAsMembership || o.AddToUsersAs > GroupAddToUsersAsSecondary {
		return util.NewValidationError(fmt.Sprintf("Invalid mode to add groups to new users: %d", o.AddToUsersAs))
	}
	return nil
}

// GetUserGroupType returns the type for the matching user group
func (o *AdminGroupMappingOptions) GetUserGroupType() int {
	switch o.AddToUsersAs {
	case GroupAddToUsersAsPrimary:
		return sdk.GroupTypePrimary
	case GroupAddToUsersAsSecondary:
		return sdk.GroupTypeSecondary
	default:
		return sdk.GroupTypeMembership
	}
}

// AdminGroupMapping defines the mapping between an SFTPGo admin and a group
type AdminGroupMapping struct {
	Name    string                   `json:"name"`
	Options AdminGroupMappingOptions `json:"options"`
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
	Email          string       `json:"email,omitempty"`
	Permissions    []string     `json:"permissions"`
	Filters        AdminFilters `json:"filters,omitempty"`
	Description    string       `json:"description,omitempty"`
	AdditionalInfo string       `json:"additional_info,omitempty"`
	// Groups membership
	Groups []AdminGroupMapping `json:"groups,omitempty"`
	// Creation time as unix timestamp in milliseconds. It will be 0 for admins created before v2.2.0
	CreatedAt int64 `json:"created_at"`
	// last update time as unix timestamp in milliseconds
	UpdatedAt int64 `json:"updated_at"`
	// Last login as unix timestamp in milliseconds
	LastLogin int64 `json:"last_login"`
}

// CountUnusedRecoveryCodes returns the number of unused recovery codes
func (a *Admin) CountUnusedRecoveryCodes() int {
	unused := 0
	for _, code := range a.Filters.RecoveryCodes {
		if !code.Used {
			unused++
		}
	}
	return unused
}

func (a *Admin) hashPassword() error {
	if a.Password != "" && !util.IsStringPrefixInSlice(a.Password, internalHashPwdPrefixes) {
		if config.PasswordValidation.Admins.MinEntropy > 0 {
			if err := passwordvalidator.Validate(a.Password, config.PasswordValidation.Admins.MinEntropy); err != nil {
				return util.NewValidationError(err.Error())
			}
		}
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

func (a *Admin) hasRedactedSecret() bool {
	return a.Filters.TOTPConfig.Secret.IsRedacted()
}

func (a *Admin) validateRecoveryCodes() error {
	for i := 0; i < len(a.Filters.RecoveryCodes); i++ {
		code := &a.Filters.RecoveryCodes[i]
		if code.Secret.IsEmpty() {
			return util.NewValidationError("mfa: recovery code cannot be empty")
		}
		if code.Secret.IsPlain() {
			code.Secret.SetAdditionalData(a.Username)
			if err := code.Secret.Encrypt(); err != nil {
				return util.NewValidationError(fmt.Sprintf("mfa: unable to encrypt recovery code: %v", err))
			}
		}
	}
	return nil
}

func (a *Admin) validatePermissions() error {
	a.Permissions = util.RemoveDuplicates(a.Permissions, false)
	if len(a.Permissions) == 0 {
		return util.NewValidationError("please grant some permissions to this admin")
	}
	if util.Contains(a.Permissions, PermAdminAny) {
		a.Permissions = []string{PermAdminAny}
	}
	for _, perm := range a.Permissions {
		if !util.Contains(validAdminPerms, perm) {
			return util.NewValidationError(fmt.Sprintf("invalid permission: %#v", perm))
		}
	}
	return nil
}

func (a *Admin) validateGroups() error {
	hasPrimary := false
	for _, g := range a.Groups {
		if g.Name == "" {
			return util.NewValidationError("group name is mandatory")
		}
		if err := g.Options.validate(); err != nil {
			return err
		}
		if g.Options.AddToUsersAs == GroupAddToUsersAsPrimary {
			if hasPrimary {
				return util.NewValidationError("only one primary group is allowed")
			}
			hasPrimary = true
		}
	}
	return nil
}

func (a *Admin) validate() error {
	a.SetEmptySecretsIfNil()
	if a.Username == "" {
		return util.NewValidationError("username is mandatory")
	}
	if err := checkReservedUsernames(a.Username); err != nil {
		return err
	}
	if a.Password == "" {
		return util.NewValidationError("please set a password")
	}
	if a.hasRedactedSecret() {
		return util.NewValidationError("cannot save an admin with a redacted secret")
	}
	if err := a.Filters.TOTPConfig.validate(a.Username); err != nil {
		return err
	}
	if err := a.validateRecoveryCodes(); err != nil {
		return err
	}
	if config.NamingRules&1 == 0 && !usernameRegex.MatchString(a.Username) {
		return util.NewValidationError(fmt.Sprintf("username %#v is not valid, the following characters are allowed: a-zA-Z0-9-_.~", a.Username))
	}
	if err := a.hashPassword(); err != nil {
		return err
	}
	if err := a.validatePermissions(); err != nil {
		return err
	}
	if a.Email != "" && !util.IsEmailValid(a.Email) {
		return util.NewValidationError(fmt.Sprintf("email %#v is not valid", a.Email))
	}
	a.Filters.AllowList = util.RemoveDuplicates(a.Filters.AllowList, false)
	for _, IPMask := range a.Filters.AllowList {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse allow list entry %#v : %v", IPMask, err))
		}
	}

	return a.validateGroups()
}

// GetGroupsAsString returns the user's groups as a string
func (a *Admin) GetGroupsAsString() string {
	if len(a.Groups) == 0 {
		return ""
	}
	var groups []string
	for _, g := range a.Groups {
		groups = append(groups, g.Name)
	}
	sort.Strings(groups)
	return strings.Join(groups, ",")
}

// CheckPassword verifies the admin password
func (a *Admin) CheckPassword(password string) (bool, error) {
	if strings.HasPrefix(a.Password, bcryptPwdPrefix) {
		if err := bcrypt.CompareHashAndPassword([]byte(a.Password), []byte(password)); err != nil {
			return false, ErrInvalidCredentials
		}
		return true, nil
	}
	match, err := argon2id.ComparePasswordAndHash(password, a.Password)
	if !match || err != nil {
		return false, ErrInvalidCredentials
	}
	return match, err
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

// CanLogin returns an error if the login is not allowed
func (a *Admin) CanLogin(ip string) error {
	if a.Status != 1 {
		return fmt.Errorf("admin %#v is disabled", a.Username)
	}
	if !a.CanLoginFromIP(ip) {
		return fmt.Errorf("login from IP %v not allowed", ip)
	}
	return nil
}

func (a *Admin) checkUserAndPass(password, ip string) error {
	if err := a.CanLogin(ip); err != nil {
		return err
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
	return nil
}

// RenderAsJSON implements the renderer interface used within plugins
func (a *Admin) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		admin, err := provider.adminExists(a.Username)
		if err != nil {
			providerLog(logger.LevelError, "unable to reload admin before rendering as json: %v", err)
			return nil, err
		}
		admin.HideConfidentialData()
		return json.Marshal(admin)
	}
	a.HideConfidentialData()
	return json.Marshal(a)
}

// HideConfidentialData hides admin confidential data
func (a *Admin) HideConfidentialData() {
	a.Password = ""
	if a.Filters.TOTPConfig.Secret != nil {
		a.Filters.TOTPConfig.Secret.Hide()
	}
	for _, code := range a.Filters.RecoveryCodes {
		if code.Secret != nil {
			code.Secret.Hide()
		}
	}
	a.SetNilSecretsIfEmpty()
}

// SetEmptySecretsIfNil sets the secrets to empty if nil
func (a *Admin) SetEmptySecretsIfNil() {
	if a.Filters.TOTPConfig.Secret == nil {
		a.Filters.TOTPConfig.Secret = kms.NewEmptySecret()
	}
}

// SetNilSecretsIfEmpty set the secrets to nil if empty.
// This is useful before rendering as JSON so the empty fields
// will not be serialized.
func (a *Admin) SetNilSecretsIfEmpty() {
	if a.Filters.TOTPConfig.Secret != nil && a.Filters.TOTPConfig.Secret.IsEmpty() {
		a.Filters.TOTPConfig.Secret = nil
	}
}

// HasPermission returns true if the admin has the specified permission
func (a *Admin) HasPermission(perm string) bool {
	if util.Contains(a.Permissions, PermAdminAny) {
		return true
	}
	return util.Contains(a.Permissions, perm)
}

// GetPermissionsAsString returns permission as string
func (a *Admin) GetPermissionsAsString() string {
	return strings.Join(a.Permissions, ", ")
}

// GetLastLoginAsString returns the last login as string
func (a *Admin) GetLastLoginAsString() string {
	if a.LastLogin > 0 {
		return util.GetTimeFromMsecSinceEpoch(a.LastLogin).UTC().Format(iso8601UTCFormat)
	}
	return ""
}

// GetAllowedIPAsString returns the allowed IP as comma separated string
func (a *Admin) GetAllowedIPAsString() string {
	return strings.Join(a.Filters.AllowList, ",")
}

// GetValidPerms returns the allowed admin permissions
func (a *Admin) GetValidPerms() []string {
	return validAdminPerms
}

// CanManageMFA returns true if the admin can add a multi-factor authentication configuration
func (a *Admin) CanManageMFA() bool {
	return len(mfa.GetAvailableTOTPConfigs()) > 0
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
	a.SetEmptySecretsIfNil()
	permissions := make([]string, len(a.Permissions))
	copy(permissions, a.Permissions)
	filters := AdminFilters{}
	filters.AllowList = make([]string, len(a.Filters.AllowList))
	filters.AllowAPIKeyAuth = a.Filters.AllowAPIKeyAuth
	filters.TOTPConfig.Enabled = a.Filters.TOTPConfig.Enabled
	filters.TOTPConfig.ConfigName = a.Filters.TOTPConfig.ConfigName
	filters.TOTPConfig.Secret = a.Filters.TOTPConfig.Secret.Clone()
	copy(filters.AllowList, a.Filters.AllowList)
	filters.RecoveryCodes = make([]RecoveryCode, 0)
	for _, code := range a.Filters.RecoveryCodes {
		if code.Secret == nil {
			code.Secret = kms.NewEmptySecret()
		}
		filters.RecoveryCodes = append(filters.RecoveryCodes, RecoveryCode{
			Secret: code.Secret.Clone(),
			Used:   code.Used,
		})
	}
	groups := make([]AdminGroupMapping, 0, len(a.Groups))
	for _, g := range a.Groups {
		groups = append(groups, AdminGroupMapping{
			Name: g.Name,
			Options: AdminGroupMappingOptions{
				AddToUsersAs: g.Options.AddToUsersAs,
			},
		})
	}

	return Admin{
		ID:             a.ID,
		Status:         a.Status,
		Username:       a.Username,
		Password:       a.Password,
		Email:          a.Email,
		Permissions:    permissions,
		Groups:         groups,
		Filters:        filters,
		AdditionalInfo: a.AdditionalInfo,
		Description:    a.Description,
		LastLogin:      a.LastLogin,
		CreatedAt:      a.CreatedAt,
		UpdatedAt:      a.UpdatedAt,
	}
}

func (a *Admin) setFromEnv() error {
	envUsername := strings.TrimSpace(os.Getenv("SFTPGO_DEFAULT_ADMIN_USERNAME"))
	envPassword := strings.TrimSpace(os.Getenv("SFTPGO_DEFAULT_ADMIN_PASSWORD"))
	if envUsername == "" || envPassword == "" {
		return errors.New(`to create the default admin you need to set the env vars "SFTPGO_DEFAULT_ADMIN_USERNAME" and "SFTPGO_DEFAULT_ADMIN_PASSWORD"`)
	}
	a.Username = envUsername
	a.Password = envPassword
	a.Status = 1
	a.Permissions = []string{PermAdminAny}
	return nil
}
