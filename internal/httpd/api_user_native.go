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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/rs/xid"

	"github.com/xrogers/gonas/v2/internal/common"
	"github.com/xrogers/gonas/v2/internal/dataprovider"
	"github.com/xrogers/gonas/v2/internal/jwt"
	"github.com/xrogers/gonas/v2/internal/logger"
	"github.com/xrogers/gonas/v2/internal/util"
)

// The REST API of the native apps: passkey sign in, the passkeys of the signed in user, search
// and thumbnails. The web pages offer the same through their own routes.

const searchTruncatedHeader = "X-GONAS-Search-Truncated"

// passkeyTokenRequest is the body of a passkey sign in through the REST API.
type passkeyTokenRequest struct {
	Token      string          `json:"token"`
	Credential json.RawMessage `json:"credential"`
}

// getUserTokenWithPasskey returns an API token for a passkey assertion made on a challenge from
// the options endpoint. If passkeys do not satisfy two-factor authentication, an account with
// TOTP must also send its code, as with a password.
func (s *httpdServer) getUserTokenWithPasskey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	failed := &dataprovider.User{}
	if err := common.Config.ExecutePostConnectHook(ipAddr, common.ProtocolHTTP); err != nil {
		updateLoginMetrics(failed, dataprovider.LoginMethodPasskey, ipAddr, err, r)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	var request passkeyTokenRequest
	if err := render.DecodeJSON(r.Body, &request); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var user, userMerged dataprovider.User
	credential, err := s.validateDiscoverableLogin(r, ipAddr, tokenAudiencePasskeyAPILogin, request.Token,
		request.Credential, func(username string) (*passkeyAccount, error) {
			var err error
			user, userMerged, err = dataprovider.GetUserVariants(username, "")
			if err != nil {
				return nil, err
			}
			failed.Username = user.Username
			if !userMerged.CanManageMFA() {
				return nil, errPasskeyDisabled
			}
			return &passkeyAccount{username: user.Username, passkeys: user.Filters.Passkeys}, nil
		})
	if err != nil {
		logger.Debug(logSender, "", "API passkey login failed: %v", err)
		updateLoginMetrics(failed, dataprovider.LoginMethodPasskey, ipAddr, dataprovider.ErrInvalidCredentials, r)
		sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, xid.New().String())
	if err := checkHTTPClientUser(&userMerged, r, connectionID, true, false); err != nil {
		updateLoginMetrics(&userMerged, dataprovider.LoginMethodPasskey, ipAddr, err, r)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if !passkeysSatisfyTwoFactor() {
		if status, err := checkUserTOTPHeader(&userMerged, r); err != nil {
			updateLoginMetrics(&userMerged, dataprovider.LoginMethodPasskey, ipAddr, err, r)
			sendAPIResponse(w, r, err, http.StatusText(status), status)
			return
		}
	}
	defer userMerged.CloseFs()
	if err := userMerged.CheckFsRoot(connectionID); err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&userMerged, dataprovider.LoginMethodPasskey, ipAddr, common.ErrInternalFailure, r)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if updatePasskeySignCount(user.Filters.Passkeys, credential) {
		if err := dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, ipAddr, user.Role); err != nil {
			logger.Warn(logSender, connectionID, "unable to update the passkey counter: %v", err)
		}
	}
	s.generateAndSendUserToken(w, r, ipAddr, userMerged, dataprovider.LoginMethodPasskey,
		userMustSetSecondFactor(&userMerged))
}

// refreshUserToken returns a new API token for a valid one, as the WebClient refreshes its
// cookie. It keeps the sign in time, so it cannot extend a session past maxTokenDuration, nor let a
// token add a passkey later than it could. The account is checked again, as on any sign in.
func (s *httpdServer) refreshUserToken(w http.ResponseWriter, r *http.Request) {
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" || claims.IssuedAt == nil {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	if time.Since(claims.IssuedAt.Time())+apiTokenDuration > maxTokenDuration {
		sendAPIResponse(w, r, nil, "Session expired, sign in again", http.StatusUnauthorized)
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if user.GetSignature() != claims.Subject {
		sendAPIResponse(w, r, nil, "Session expired, sign in again", http.StatusUnauthorized)
		return
	}
	if err := user.CheckLoginConditions(); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if err := checkHTTPClientUser(&user, r, xid.New().String(), true, false); err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	claims.Permissions = user.Filters.WebClient
	claims.Role = user.Role
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	token, err := s.tokenAuth.SignWithParams(claims, tokenAudienceAPIUser, ipAddr, apiTokenDuration)
	if err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, claims.BuildTokenResponse(token))
}

// apiPasskey is a passkey of the signed in user as the REST API lists it.
type apiPasskey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
}

func getUserPasskeys(w http.ResponseWriter, r *http.Request) {
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	passkeys := make([]apiPasskey, 0, len(user.Filters.Passkeys))
	for _, p := range user.Filters.Passkeys {
		passkeys = append(passkeys, apiPasskey{
			ID:        base64.RawURLEncoding.EncodeToString(p.ID),
			Name:      p.Name,
			CreatedAt: p.CreatedAt,
		})
	}
	render.JSON(w, r, passkeys)
}

// searchUserFiles finds the files and folders whose names match q under path, in the format of a
// folder listing plus the folder each one is in. Results stop at a safety cap, and the response
// then has the X-GONAS-Search-Truncated header.
func searchUserFiles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	defer common.Connections.Remove(connection.GetID())

	startDir := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	results := make([]map[string]any, 0)
	if q != "" {
		truncated, aborted := walkSearch(r.Context(), connection, startDir, q, func(dir string, info os.FileInfo) bool {
			res := map[string]any{
				"name":          info.Name(),
				"path":          dir,
				"mode":          info.Mode(),
				"last_modified": info.ModTime().UTC().Format(time.RFC3339),
			}
			if info.Mode().IsRegular() {
				res["size"] = info.Size()
			}
			results = append(results, res)
			return len(results) < maxSearchResults
		})
		if aborted {
			return
		}
		if truncated {
			w.Header().Set(searchTruncatedHeader, "true")
		}
	}
	render.JSON(w, r, results)
}
