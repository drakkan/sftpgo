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

func getRoles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	roles, err := dataprovider.GetRoles(limit, offset, order, false)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, roles)
}

func addRole(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	var role dataprovider.Role
	err = render.DecodeJSON(r.Body, &role)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.AddRole(&role, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
	} else {
		w.Header().Add("Location", fmt.Sprintf("%s/%s", rolesPath, url.PathEscape(role.Name)))
		renderRole(w, r, role.Name, http.StatusCreated)
	}
}

func updateRole(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	name := getURLParam(r, "name")
	role, err := dataprovider.RoleExists(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	var updatedRole dataprovider.Role
	err = render.DecodeJSON(r.Body, &updatedRole)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	updatedRole.ID = role.ID
	updatedRole.Name = role.Name
	err = dataprovider.UpdateRole(&updatedRole, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Role updated", http.StatusOK)
}

func renderRole(w http.ResponseWriter, r *http.Request, name string, status int) {
	role, err := dataprovider.RoleExists(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, status)
		render.JSON(w, r.WithContext(ctx), role)
	} else {
		render.JSON(w, r, role)
	}
}

func getRoleByName(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	renderRole(w, r, name, http.StatusOK)
}

func deleteRole(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	name := getURLParam(r, "name")
	err = dataprovider.DeleteRole(name, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr), claims.Role)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Role deleted", http.StatusOK)
}
