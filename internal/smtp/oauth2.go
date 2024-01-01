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

// Package smtp provides supports for sending emails
package smtp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

// Supported OAuth2 providers
const (
	OAuth2ProviderGoogle = iota
	OAuth2ProviderMicrosoft
)

var supportedOAuth2Providers = []int{OAuth2ProviderGoogle, OAuth2ProviderMicrosoft}

// OAuth2Config defines OAuth2 settings
type OAuth2Config struct {
	Provider int `json:"provider" mapstructure:"provider"`
	// Tenant for Microsoft provider, if empty "common" is used
	Tenant string `json:"tenant" mapstructure:"tenant"`
	// ClientID is the application's ID
	ClientID string `json:"client_id" mapstructure:"client_id"`
	// ClientSecret is the application's secret
	ClientSecret string `json:"client_secret" mapstructure:"client_secret"`
	// Token to use to get/renew access tokens
	RefreshToken string `json:"refresh_token" mapstructure:"refresh_token"`
	mu           *sync.RWMutex
	config       *oauth2.Config
	accessToken  *oauth2.Token
}

// Validate validates and initializes the configuration
func (c *OAuth2Config) Validate() error {
	if !util.Contains(supportedOAuth2Providers, c.Provider) {
		return fmt.Errorf("smtp oauth2: unsupported provider %d", c.Provider)
	}
	if c.ClientID == "" {
		return errors.New("smtp oauth2: client id is required")
	}
	if c.ClientSecret == "" {
		return errors.New("smtp oauth2: client secret is required")
	}
	if c.RefreshToken == "" {
		return errors.New("smtp oauth2: refresh token is required")
	}
	c.initialize()
	return nil
}

func (c *OAuth2Config) isEqual(other *OAuth2Config) bool {
	if c.Provider != other.Provider {
		return false
	}
	if c.Tenant != other.Tenant {
		return false
	}
	if c.ClientID != other.ClientID {
		return false
	}
	if c.ClientSecret != other.ClientSecret {
		return false
	}
	if c.RefreshToken != other.RefreshToken {
		return false
	}
	return true
}

func (c *OAuth2Config) getAccessToken() (string, error) {
	c.mu.RLock()
	if c.accessToken.Expiry.After(time.Now().Add(30 * time.Second)) {
		accessToken := c.accessToken.AccessToken
		c.mu.RUnlock()

		return accessToken, nil
	}
	logger.Debug(logSender, "", "renew oauth2 token required, current token expires at %s", c.accessToken.Expiry)
	token := new(oauth2.Token)
	*token = *c.accessToken
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	newToken, err := c.config.TokenSource(ctx, token).Token()
	if err != nil {
		logger.Error(logSender, "", "unable to get new token: %v", err)
		return "", err
	}
	accessToken := newToken.AccessToken
	refreshToken := newToken.RefreshToken
	if refreshToken != "" && refreshToken != token.RefreshToken {
		c.mu.Lock()
		c.RefreshToken = refreshToken
		c.accessToken = newToken
		c.mu.Unlock()

		logger.Debug(logSender, "", "oauth2 refresh token changed")
		go updateRefreshToken(refreshToken)
	}
	if accessToken != token.AccessToken {
		c.mu.Lock()
		c.accessToken = newToken
		c.mu.Unlock()

		logger.Debug(logSender, "", "new oauth2 token saved, expires at %s", c.accessToken.Expiry)
	}
	return accessToken, nil
}

func (c *OAuth2Config) initialize() {
	c.mu = new(sync.RWMutex)
	c.config = c.GetOAuth2()
	c.accessToken = &oauth2.Token{
		TokenType:    "Bearer",
		RefreshToken: c.RefreshToken,
	}
}

// GetOAuth2 returns the oauth2 configuration for the provided parameters.
func (c *OAuth2Config) GetOAuth2() *oauth2.Config {
	var endpoint oauth2.Endpoint
	var scopes []string

	switch c.Provider {
	case OAuth2ProviderMicrosoft:
		endpoint = microsoft.AzureADEndpoint(c.Tenant)
		scopes = []string{"offline_access", "https://outlook.office.com/SMTP.Send"}
	default:
		endpoint = google.Endpoint
		scopes = []string{"https://mail.google.com/"}
	}

	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       scopes,
		Endpoint:     endpoint,
	}
}
