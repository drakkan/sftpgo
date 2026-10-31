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

package httpd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/jwt"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

// userAPIKeyRequest lists the only fields a user can set on their own key.
// Scope and owner come from the token, so they are not read from the request.
type userAPIKeyRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Milliseconds since the epoch, 0 means the key never expires
	ExpiresAt int64 `json:"expires_at"`
	// If true the key can also open a WebClient session, see createUserWebSession
	WebSession bool `json:"web_session"`
}

func addUserAPIKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !user.Filters.AllowAPIKeyAuth {
		sendAPIResponse(w, r, nil, "API key authentication is disabled for this user", http.StatusForbidden)
		return
	}
	var req userAPIKeyRequest
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if req.ExpiresAt != 0 && req.ExpiresAt <= util.GetTimeAsMsSinceEpoch(time.Now()) {
		sendAPIResponse(w, r, nil, "expires_at must be in the future", http.StatusBadRequest)
		return
	}
	scope := dataprovider.APIKeyScopeUser
	if req.WebSession {
		scope = dataprovider.APIKeyScopeUserWebSession
	}
	apiKey := dataprovider.APIKey{
		Name:        req.Name,
		Description: req.Description,
		ExpiresAt:   req.ExpiresAt,
		Scope:       scope,
		User:        claims.Username,
	}
	err = dataprovider.AddAPIKey(&apiKey, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	response := map[string]string{
		"message": "API key created. This is the only time the API key is visible, please save it.",
		"key":     apiKey.DisplayKey(),
	}
	w.Header().Add("Location", fmt.Sprintf("%s/%s", userAPIKeysPath, url.PathEscape(apiKey.KeyID)))
	w.Header().Add("X-Object-ID", apiKey.KeyID)
	ctx := context.WithValue(r.Context(), render.StatusCtxKey, http.StatusCreated)
	render.JSON(w, r.WithContext(ctx), response)
}

func deleteUserAPIKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	keyID := getURLParam(r, "id")
	apiKey, err := dataprovider.APIKeyExists(keyID)
	if err != nil && !errors.Is(err, util.ErrNotFound) {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	// Keys of others get the same answer as unknown keys, so IDs cannot be probed.
	if err != nil || !apiKey.IsForUser() || apiKey.User != claims.Username {
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	// A key can revoke itself, so that an app can sign out without the password,
	// but it cannot revoke the keys of other devices.
	if claims.APIKeyID != "" && claims.APIKeyID != keyID {
		sendAPIResponse(w, r, nil, "An API key can only revoke itself", http.StatusForbidden)
		return
	}
	err = dataprovider.DeleteAPIKey(keyID, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "API key deleted", http.StatusOK)
}

// getUserAPIKeys returns the keys bound to the logged-in user. The provider has no filter by
// owner, so the keys are read page by page.
func getUserAPIKeys(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	keys := make([]dataprovider.APIKey, 0)
	for offset := 0; ; offset += defaultQueryLimit {
		page, err := dataprovider.GetAPIKeys(defaultQueryLimit, offset, dataprovider.OrderDESC)
		if err != nil {
			sendAPIResponse(w, r, err, "", getRespStatus(err))
			return
		}
		for idx := range page {
			if page[idx].IsForUser() && page[idx].User == claims.Username {
				page[idx].HideConfidentialData()
				keys = append(keys, page[idx])
			}
		}
		if len(page) < defaultQueryLimit {
			break
		}
	}
	render.JSON(w, r, keys)
}

func (s *httpdServer) handleClientGetAPIKeys(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	data := clientAPIKeysPage{
		baseClientPage:  s.getBaseClientPageData(util.I18nAPIKeysTitle, webClientAPIKeysPath, w, r),
		AllowAPIKeyAuth: user.Filters.AllowAPIKeyAuth,
	}
	renderClientTemplate(w, templateClientAPIKeys, data)
}

// createUserWebSession sets the WebClient cookie for the user of the API key in use.
// The key replaces both the password and the second factor, this is why only keys
// created for this purpose are accepted, and why the session cannot change the
// account: see forbidAPIKeySession and checkWebSessionAPIKey.
func (s *httpdServer) createUserWebSession(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	if claims.APIKeyID == "" {
		sendAPIResponse(w, r, nil, "An API key is required", http.StatusForbidden)
		return
	}
	apiKey, err := dataprovider.APIKeyExists(claims.APIKeyID)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if !apiKey.CanOpenWebSession(claims.Username) {
		sendAPIResponse(w, r, nil, "This API key cannot open web sessions", http.StatusForbidden)
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	// These pages are closed to key sessions, so the user must log in to get past them.
	if user.MustChangePassword() || user.MustSetSecondFactor() {
		sendAPIResponse(w, r, nil, "Login with the password required", http.StatusForbidden)
		return
	}
	session := &jwt.Claims{
		Username:                   user.Username,
		Permissions:                user.Filters.WebClient,
		Role:                       user.Role,
		APIKeyID:                   apiKey.KeyID,
		RequiredTwoFactorProtocols: user.Filters.TwoFactorAuthProtocols,
	}
	session.Subject = user.GetSignature()
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := createAndSetCookie(w, r, session, s.tokenAuth, tokenAudienceWebClient, ipAddr); err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	logger.Info(logSender, "", "WebClient session opened for user %q with API key %q from %q", user.Username,
		apiKey.KeyID, ipAddr)
	sendAPIResponse(w, r, nil, "Web session created", http.StatusOK)
}
