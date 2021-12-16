package dataprovider

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

// APIKeyScope defines the supported API key scopes
type APIKeyScope int

// Supported API key scopes
const (
	// the API key will be used for an admin
	APIKeyScopeAdmin APIKeyScope = iota + 1
	// the API key will be used for a user
	APIKeyScopeUser
)

// APIKey defines a SFTPGo API key.
// API keys can be used as authentication alternative to short lived tokens
// for REST API
type APIKey struct {
	// Database unique identifier
	ID int64 `json:"-"`
	// Unique key identifier, used for key lookups.
	// The generated key is in the format `KeyID.hash(Key)` so we can split
	// and lookup by KeyID and then verify if the key matches the recorded hash
	KeyID string `json:"id"`
	// User friendly key name
	Name string `json:"name"`
	// we store the hash of the key, this is just like a password
	Key       string      `json:"key,omitempty"`
	Scope     APIKeyScope `json:"scope"`
	CreatedAt int64       `json:"created_at"`
	UpdatedAt int64       `json:"updated_at"`
	// 0 means never used
	LastUseAt int64 `json:"last_use_at,omitempty"`
	// 0 means never expire
	ExpiresAt   int64  `json:"expires_at,omitempty"`
	Description string `json:"description,omitempty"`
	// Username associated with this API key.
	// If empty and the scope is APIKeyScopeUser the key is valid for any user
	User string `json:"user,omitempty"`
	// Admin username associated with this API key.
	// If empty and the scope is APIKeyScopeAdmin the key is valid for any admin
	Admin string `json:"admin,omitempty"`
	// these fields are for internal use
	userID   int64
	adminID  int64
	plainKey string
}

func (k *APIKey) getACopy() APIKey {
	return APIKey{
		ID:          k.ID,
		KeyID:       k.KeyID,
		Name:        k.Name,
		Key:         k.Key,
		Scope:       k.Scope,
		CreatedAt:   k.CreatedAt,
		UpdatedAt:   k.UpdatedAt,
		LastUseAt:   k.LastUseAt,
		ExpiresAt:   k.ExpiresAt,
		Description: k.Description,
		User:        k.User,
		Admin:       k.Admin,
		userID:      k.userID,
		adminID:     k.adminID,
	}
}

// RenderAsJSON implements the renderer interface used within plugins
func (k *APIKey) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		apiKey, err := provider.apiKeyExists(k.KeyID)
		if err != nil {
			providerLog(logger.LevelError, "unable to reload api key before rendering as json: %v", err)
			return nil, err
		}
		apiKey.HideConfidentialData()
		return json.Marshal(apiKey)
	}
	k.HideConfidentialData()
	return json.Marshal(k)
}

// HideConfidentialData hides API key confidential data
func (k *APIKey) HideConfidentialData() {
	k.Key = ""
}

func (k *APIKey) hashKey() error {
	if k.Key != "" && !util.IsStringPrefixInSlice(k.Key, internalHashPwdPrefixes) {
		if config.PasswordHashing.Algo == HashingAlgoBcrypt {
			hashed, err := bcrypt.GenerateFromPassword([]byte(k.Key), config.PasswordHashing.BcryptOptions.Cost)
			if err != nil {
				return err
			}
			k.Key = string(hashed)
		} else {
			hashed, err := argon2id.CreateHash(k.Key, argon2Params)
			if err != nil {
				return err
			}
			k.Key = hashed
		}
	}
	return nil
}

func (k *APIKey) generateKey() {
	if k.KeyID != "" || k.Key != "" {
		return
	}
	k.KeyID = util.GenerateUniqueID()
	k.Key = util.GenerateUniqueID()
	k.plainKey = k.Key
}

// DisplayKey returns the key to show to the user
func (k *APIKey) DisplayKey() string {
	return fmt.Sprintf("%v.%v", k.KeyID, k.plainKey)
}

func (k *APIKey) validate() error {
	if k.Name == "" {
		return util.NewValidationError("name is mandatory")
	}
	if k.Scope != APIKeyScopeAdmin && k.Scope != APIKeyScopeUser {
		return util.NewValidationError(fmt.Sprintf("invalid scope: %v", k.Scope))
	}
	k.generateKey()
	if err := k.hashKey(); err != nil {
		return err
	}
	if k.User != "" && k.Admin != "" {
		return util.NewValidationError("an API key can be related to a user or an admin, not both")
	}
	if k.Scope == APIKeyScopeAdmin {
		k.User = ""
	}
	if k.Scope == APIKeyScopeUser {
		k.Admin = ""
	}
	if k.User != "" {
		_, err := provider.userExists(k.User)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("unable to check API key user %v: %v", k.User, err))
		}
	}
	if k.Admin != "" {
		_, err := provider.adminExists(k.Admin)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("unable to check API key admin %v: %v", k.Admin, err))
		}
	}
	return nil
}

// Authenticate tries to authenticate the provided plain key
func (k *APIKey) Authenticate(plainKey string) error {
	if k.ExpiresAt > 0 && k.ExpiresAt < util.GetTimeAsMsSinceEpoch(time.Now()) {
		return fmt.Errorf("API key %#v is expired, expiration timestamp: %v current timestamp: %v", k.KeyID,
			k.ExpiresAt, util.GetTimeAsMsSinceEpoch(time.Now()))
	}
	if strings.HasPrefix(k.Key, bcryptPwdPrefix) {
		if err := bcrypt.CompareHashAndPassword([]byte(k.Key), []byte(plainKey)); err != nil {
			return ErrInvalidCredentials
		}
	} else if strings.HasPrefix(k.Key, argonPwdPrefix) {
		match, err := argon2id.ComparePasswordAndHash(plainKey, k.Key)
		if err != nil || !match {
			return ErrInvalidCredentials
		}
	}

	return nil
}
