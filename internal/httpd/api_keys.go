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
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func getAPIKeys(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	apiKeys, err := dataprovider.GetAPIKeys(limit, offset, order)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	render.JSON(w, r, apiKeys)
}

func getAPIKeyByID(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	keyID := getURLParam(r, "id")
	apiKey, err := dataprovider.APIKeyExists(keyID)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	apiKey.HideConfidentialData()

	render.JSON(w, r, apiKey)
}

func addAPIKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	var apiKey dataprovider.APIKey
	err = render.DecodeJSON(r.Body, &apiKey)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	apiKey.ID = 0
	apiKey.KeyID = ""
	apiKey.Key = ""
	apiKey.LastUseAt = 0
	err = dataprovider.AddAPIKey(&apiKey, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	response := make(map[string]string)
	response["message"] = "API key created. This is the only time the API key is visible, please save it."
	response["key"] = apiKey.DisplayKey()
	w.Header().Add("Location", fmt.Sprintf("%s/%s", apiKeysPath, url.PathEscape(apiKey.KeyID)))
	w.Header().Add("X-Object-ID", apiKey.KeyID)
	ctx := context.WithValue(r.Context(), render.StatusCtxKey, http.StatusCreated)
	render.JSON(w, r.WithContext(ctx), response)
}

func updateAPIKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	keyID := getURLParam(r, "id")
	apiKey, err := dataprovider.APIKeyExists(keyID)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	var updatedAPIKey dataprovider.APIKey
	err = render.DecodeJSON(r.Body, &updatedAPIKey)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	updatedAPIKey.KeyID = keyID
	updatedAPIKey.Key = apiKey.Key
	err = dataprovider.UpdateAPIKey(&updatedAPIKey, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "API key updated", http.StatusOK)
}

func deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	keyID := getURLParam(r, "id")
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	err = dataprovider.DeleteAPIKey(keyID, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "API key deleted", http.StatusOK)
}
