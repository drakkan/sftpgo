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

package dataprovider

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

// ShareScope defines the supported share scopes
type ShareScope int

// Supported share scopes
const (
	ShareScopeRead ShareScope = iota + 1
	ShareScopeWrite
	ShareScopeReadWrite
)

const (
	redactedPassword = "[**redacted**]"
)

// Share defines files and or directories shared with external users
type Share struct {
	// Database unique identifier
	ID int64 `json:"-"`
	// Unique ID used to access this object
	ShareID     string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Scope       ShareScope `json:"scope"`
	// Paths to files or directories, for ShareScopeWrite it must be exactly one directory
	Paths []string `json:"paths"`
	// Username who shared this object
	Username  string `json:"username"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	// 0 means never used
	LastUseAt int64 `json:"last_use_at,omitempty"`
	// ExpiresAt expiration date/time as unix timestamp in milliseconds, 0 means no expiration
	ExpiresAt int64 `json:"expires_at,omitempty"`
	// Optional password to protect the share
	Password string `json:"password"`
	// Limit the available access tokens, 0 means no limit
	MaxTokens int `json:"max_tokens,omitempty"`
	// Used tokens
	UsedTokens int `json:"used_tokens,omitempty"`
	// Limit the share availability to these IPs/CIDR networks
	AllowFrom []string `json:"allow_from,omitempty"`
	// set for restores, we don't have to validate the expiration date
	// otherwise we fail to restore existing shares and we have to insert
	// all the previous values with no modifications
	IsRestore bool `json:"-"`
}

// IsExpired returns true if the share is expired
func (s *Share) IsExpired() bool {
	if s.ExpiresAt > 0 {
		return s.ExpiresAt < util.GetTimeAsMsSinceEpoch(time.Now())
	}
	return false
}

// GetAllowedFromAsString returns the allowed IP as comma separated string
func (s *Share) GetAllowedFromAsString() string {
	return strings.Join(s.AllowFrom, ",")
}

func (s *Share) getACopy() Share {
	allowFrom := make([]string, len(s.AllowFrom))
	copy(allowFrom, s.AllowFrom)

	return Share{
		ID:          s.ID,
		ShareID:     s.ShareID,
		Name:        s.Name,
		Description: s.Description,
		Scope:       s.Scope,
		Paths:       s.Paths,
		Username:    s.Username,
		CreatedAt:   s.CreatedAt,
		UpdatedAt:   s.UpdatedAt,
		LastUseAt:   s.LastUseAt,
		ExpiresAt:   s.ExpiresAt,
		Password:    s.Password,
		MaxTokens:   s.MaxTokens,
		UsedTokens:  s.UsedTokens,
		AllowFrom:   allowFrom,
	}
}

// RenderAsJSON implements the renderer interface used within plugins
func (s *Share) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		share, err := provider.shareExists(s.ShareID, s.Username)
		if err != nil {
			providerLog(logger.LevelError, "unable to reload share before rendering as json: %v", err)
			return nil, err
		}
		share.HideConfidentialData()
		return json.Marshal(share)
	}
	s.HideConfidentialData()
	return json.Marshal(s)
}

// HideConfidentialData hides share confidential data
func (s *Share) HideConfidentialData() {
	if s.Password != "" {
		s.Password = redactedPassword
	}
}

// HasRedactedPassword returns true if this share has a redacted password
func (s *Share) HasRedactedPassword() bool {
	return s.Password == redactedPassword
}

func (s *Share) hashPassword() error {
	if s.Password != "" && !util.IsStringPrefixInSlice(s.Password, internalHashPwdPrefixes) {
		user, err := UserExists(s.Username, "")
		if err != nil {
			return util.NewGenericError(fmt.Sprintf("unable to validate user: %v", err))
		}
		if minEntropy := user.getMinPasswordEntropy(); minEntropy > 0 {
			if err := passwordvalidator.Validate(s.Password, minEntropy); err != nil {
				return util.NewI18nError(util.NewValidationError(err.Error()), util.I18nErrorPasswordComplexity)
			}
		}
		if config.PasswordHashing.Algo == HashingAlgoBcrypt {
			hashed, err := bcrypt.GenerateFromPassword([]byte(s.Password), config.PasswordHashing.BcryptOptions.Cost)
			if err != nil {
				return err
			}
			s.Password = string(hashed)
		} else {
			hashed, err := argon2id.CreateHash(s.Password, argon2Params)
			if err != nil {
				return err
			}
			s.Password = hashed
		}
	}
	return nil
}

func (s *Share) validatePaths() error {
	var paths []string
	for _, p := range s.Paths {
		if strings.TrimSpace(p) != "" {
			paths = append(paths, p)
		}
	}
	s.Paths = paths
	if len(s.Paths) == 0 {
		return util.NewI18nError(util.NewValidationError("at least a shared path is required"), util.I18nErrorSharePathRequired)
	}
	for idx := range s.Paths {
		s.Paths[idx] = util.CleanPath(s.Paths[idx])
	}
	s.Paths = util.RemoveDuplicates(s.Paths, false)
	if s.Scope >= ShareScopeWrite && len(s.Paths) != 1 {
		return util.NewI18nError(util.NewValidationError("the write share scope requires exactly one path"), util.I18nErrorShareWriteScope)
	}
	// check nested paths
	if len(s.Paths) > 1 {
		for idx := range s.Paths {
			for innerIdx := range s.Paths {
				if idx == innerIdx {
					continue
				}
				if s.Paths[idx] == "/" || s.Paths[innerIdx] == "/" || util.IsDirOverlapped(s.Paths[idx], s.Paths[innerIdx], true, "/") {
					return util.NewI18nError(util.NewGenericError("shared paths cannot be nested"), util.I18nErrorShareNestedPaths)
				}
			}
		}
	}
	return nil
}

func (s *Share) validate() error {
	if s.ShareID == "" {
		return util.NewValidationError("share_id is mandatory")
	}
	if s.Name == "" {
		return util.NewI18nError(util.NewValidationError("name is mandatory"), util.I18nErrorNameRequired)
	}
	if s.Scope < ShareScopeRead || s.Scope > ShareScopeReadWrite {
		return util.NewI18nError(util.NewValidationError(fmt.Sprintf("invalid scope: %v", s.Scope)), util.I18nErrorShareScope)
	}
	if err := s.validatePaths(); err != nil {
		return err
	}
	if s.ExpiresAt > 0 {
		if !s.IsRestore && s.ExpiresAt < util.GetTimeAsMsSinceEpoch(time.Now()) {
			return util.NewI18nError(util.NewValidationError("expiration must be in the future"), util.I18nErrorShareExpirationPast)
		}
	} else {
		s.ExpiresAt = 0
	}
	if s.MaxTokens < 0 {
		return util.NewI18nError(util.NewValidationError("invalid max tokens"), util.I18nErrorShareMaxTokens)
	}
	if s.Username == "" {
		return util.NewI18nError(util.NewValidationError("username is mandatory"), util.I18nErrorUsernameRequired)
	}
	if s.HasRedactedPassword() {
		return util.NewValidationError("cannot save a share with a redacted password")
	}
	if err := s.hashPassword(); err != nil {
		return err
	}
	s.AllowFrom = util.RemoveDuplicates(s.AllowFrom, false)
	for _, IPMask := range s.AllowFrom {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not parse allow from entry %q : %v", IPMask, err)),
				util.I18nErrorInvalidIPMask,
			)
		}
	}
	return nil
}

// CheckCredentials verifies the share credentials if a password if set
func (s *Share) CheckCredentials(password string) (bool, error) {
	if s.Password == "" {
		return true, nil
	}
	if password == "" {
		return false, ErrInvalidCredentials
	}
	if strings.HasPrefix(s.Password, bcryptPwdPrefix) {
		if err := bcrypt.CompareHashAndPassword([]byte(s.Password), []byte(password)); err != nil {
			return false, ErrInvalidCredentials
		}
		return true, nil
	}
	match, err := argon2id.ComparePasswordAndHash(password, s.Password)
	if !match || err != nil {
		return false, ErrInvalidCredentials
	}
	return match, err
}

// GetRelativePath returns the specified absolute path as relative to the share base path
func (s *Share) GetRelativePath(name string) string {
	if len(s.Paths) == 0 {
		return ""
	}
	return util.CleanPath(strings.TrimPrefix(name, s.Paths[0]))
}

// IsUsable checks if the share is usable from the specified IP
func (s *Share) IsUsable(ip string) (bool, error) {
	if s.MaxTokens > 0 && s.UsedTokens >= s.MaxTokens {
		return false, util.NewI18nError(util.NewRecordNotFoundError("max share usage exceeded"), util.I18nErrorShareUsage)
	}
	if s.ExpiresAt > 0 {
		if s.ExpiresAt < util.GetTimeAsMsSinceEpoch(time.Now()) {
			return false, util.NewI18nError(util.NewRecordNotFoundError("share expired"), util.I18nErrorShareExpired)
		}
	}
	if len(s.AllowFrom) == 0 {
		return true, nil
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, util.NewI18nError(ErrLoginNotAllowedFromIP, util.I18nErrorLoginFromIPDenied)
	}
	for _, ipMask := range s.AllowFrom {
		_, network, err := net.ParseCIDR(ipMask)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true, nil
		}
	}
	return false, util.NewI18nError(ErrLoginNotAllowedFromIP, util.I18nErrorLoginFromIPDenied)
}
