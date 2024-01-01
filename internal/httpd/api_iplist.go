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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func getIPListEntries(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit, _, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}
	listType, _, err := getIPListPathParams(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	entries, err := dataprovider.GetIPListEntries(listType, r.URL.Query().Get("filter"), r.URL.Query().Get("from"),
		order, limit)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	render.JSON(w, r, entries)
}

func getIPListEntry(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	listType, ipOrNet, err := getIPListPathParams(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	entry, err := dataprovider.IPListEntryExists(ipOrNet, listType)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	render.JSON(w, r, entry)
}

func addIPListEntry(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	var entry dataprovider.IPListEntry
	err = render.DecodeJSON(r.Body, &entry)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.AddIPListEntry(&entry, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	w.Header().Add("Location", fmt.Sprintf("%s/%d/%s", ipListsPath, entry.Type, url.PathEscape(entry.IPOrNet)))
	sendAPIResponse(w, r, nil, "Entry added", http.StatusCreated)
}

func updateIPListEntry(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	listType, ipOrNet, err := getIPListPathParams(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	entry, err := dataprovider.IPListEntryExists(ipOrNet, listType)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	var updatedEntry dataprovider.IPListEntry
	err = render.DecodeJSON(r.Body, &updatedEntry)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	updatedEntry.Type = entry.Type
	updatedEntry.IPOrNet = entry.IPOrNet
	err = dataprovider.UpdateIPListEntry(&updatedEntry, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Entry updated", http.StatusOK)
}

func deleteIPListEntry(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	listType, ipOrNet, err := getIPListPathParams(r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.DeleteIPListEntry(ipOrNet, listType, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr),
		claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Entry deleted", http.StatusOK)
}

func getIPListPathParams(r *http.Request) (dataprovider.IPListType, string, error) {
	listTypeString := chi.URLParam(r, "type")
	listType, err := strconv.Atoi(listTypeString)
	if err != nil {
		return dataprovider.IPListType(listType), "", errors.New("invalid list type")
	}
	if err := dataprovider.CheckIPListType(dataprovider.IPListType(listType)); err != nil {
		return dataprovider.IPListType(listType), "", err
	}
	return dataprovider.IPListType(listType), getURLParam(r, "ipornet"), nil
}
