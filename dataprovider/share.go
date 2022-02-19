package dataprovider

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

// ShareScope defines the supported share scopes
type ShareScope int

// Supported share scopes
const (
	ShareScopeRead ShareScope = iota + 1
	ShareScopeWrite
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

// GetScopeAsString returns the share's scope as string.
// Used in web pages
func (s *Share) GetScopeAsString() string {
	switch s.Scope {
	case ShareScopeRead:
		return "Read"
	default:
		return "Write"
	}
}

// IsExpired returns true if the share is expired
func (s *Share) IsExpired() bool {
	if s.ExpiresAt > 0 {
		return s.ExpiresAt < util.GetTimeAsMsSinceEpoch(time.Now())
	}
	return false
}

// GetInfoString returns share's info as string.
func (s *Share) GetInfoString() string {
	var result strings.Builder
	if s.ExpiresAt > 0 {
		t := util.GetTimeFromMsecSinceEpoch(s.ExpiresAt)
		result.WriteString(fmt.Sprintf("Expiration: %v. ", t.Format("2006-01-02 15:04"))) // YYYY-MM-DD HH:MM
	}
	if s.LastUseAt > 0 {
		t := util.GetTimeFromMsecSinceEpoch(s.LastUseAt)
		result.WriteString(fmt.Sprintf("Last use: %v. ", t.Format("2006-01-02 15:04")))
	}
	if s.MaxTokens > 0 {
		result.WriteString(fmt.Sprintf("Usage: %v/%v. ", s.UsedTokens, s.MaxTokens))
	} else {
		result.WriteString(fmt.Sprintf("Used tokens: %v. ", s.UsedTokens))
	}
	if len(s.AllowFrom) > 0 {
		result.WriteString(fmt.Sprintf("Allowed IP/Mask: %v. ", len(s.AllowFrom)))
	}
	if s.Password != "" {
		result.WriteString("Password protected.")
	}
	return result.String()
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
		p = strings.TrimSpace(p)
		if p != "" {
			paths = append(paths, p)
		}
	}
	s.Paths = paths
	if len(s.Paths) == 0 {
		return util.NewValidationError("at least a shared path is required")
	}
	for idx := range s.Paths {
		s.Paths[idx] = util.CleanPath(s.Paths[idx])
	}
	s.Paths = util.RemoveDuplicates(s.Paths)
	if s.Scope == ShareScopeWrite && len(s.Paths) != 1 {
		return util.NewValidationError("the write share scope requires exactly one path")
	}
	// check nested paths
	if len(s.Paths) > 1 {
		for idx := range s.Paths {
			for innerIdx := range s.Paths {
				if idx == innerIdx {
					continue
				}
				if isVirtualDirOverlapped(s.Paths[idx], s.Paths[innerIdx], true) {
					return util.NewGenericError("shared paths cannot be nested")
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
		return util.NewValidationError("name is mandatory")
	}
	if s.Scope != ShareScopeRead && s.Scope != ShareScopeWrite {
		return util.NewValidationError(fmt.Sprintf("invalid scope: %v", s.Scope))
	}
	if err := s.validatePaths(); err != nil {
		return err
	}
	if s.ExpiresAt > 0 {
		if !s.IsRestore && s.ExpiresAt < util.GetTimeAsMsSinceEpoch(time.Now()) {
			return util.NewValidationError("expiration must be in the future")
		}
	} else {
		s.ExpiresAt = 0
	}
	if s.MaxTokens < 0 {
		return util.NewValidationError("invalid max tokens")
	}
	if s.Username == "" {
		return util.NewValidationError("username is mandatory")
	}
	if s.HasRedactedPassword() {
		return util.NewValidationError("cannot save a share with a redacted password")
	}
	if err := s.hashPassword(); err != nil {
		return err
	}
	s.AllowFrom = util.RemoveDuplicates(s.AllowFrom)
	for _, IPMask := range s.AllowFrom {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse allow from entry %#v : %v", IPMask, err))
		}
	}
	return nil
}

// CheckCredentials verifies the share credentials if a password if set
func (s *Share) CheckCredentials(username, password string) (bool, error) {
	if s.Password == "" {
		return true, nil
	}
	if username == "" || password == "" {
		return false, ErrInvalidCredentials
	}
	if username != s.Username {
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
		return false, util.NewRecordNotFoundError("max share usage exceeded")
	}
	if s.ExpiresAt > 0 {
		if s.ExpiresAt < util.GetTimeAsMsSinceEpoch(time.Now()) {
			return false, util.NewRecordNotFoundError("share expired")
		}
	}
	if len(s.AllowFrom) == 0 {
		return true, nil
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, ErrLoginNotAllowedFromIP
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
	return false, ErrLoginNotAllowedFromIP
}
