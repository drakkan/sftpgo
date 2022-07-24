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

package httpd

import (
	"context"
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func getEventActions(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	actions, err := dataprovider.GetEventActions(limit, offset, order, false)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, actions)
}

func renderEventAction(w http.ResponseWriter, r *http.Request, name string, status int) {
	action, err := dataprovider.EventActionExists(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	action.PrepareForRendering()
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, status)
		render.JSON(w, r.WithContext(ctx), action)
	} else {
		render.JSON(w, r, action)
	}
}

func getEventActionByName(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	renderEventAction(w, r, name, http.StatusOK)
}

func addEventAction(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	var action dataprovider.BaseEventAction
	err = render.DecodeJSON(r.Body, &action)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.AddEventAction(&action, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	renderEventAction(w, r, action.Name, http.StatusCreated)
}

func updateEventAction(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	name := getURLParam(r, "name")
	action, err := dataprovider.EventActionExists(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	actionID := action.ID
	name = action.Name
	currentHTTPPassword := action.Options.HTTPConfig.Password
	action.Options = dataprovider.BaseEventActionOptions{}

	err = render.DecodeJSON(r.Body, &action)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	action.ID = actionID
	action.Name = name
	action.Options.SetEmptySecretsIfNil()
	switch action.Type {
	case dataprovider.ActionTypeHTTP:
		if action.Options.HTTPConfig.Password.IsNotPlainAndNotEmpty() {
			action.Options.HTTPConfig.Password = currentHTTPPassword
		}
	}

	err = dataprovider.UpdateEventAction(&action, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Event target updated", http.StatusOK)
}

func deleteEventAction(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	name := getURLParam(r, "name")
	err = dataprovider.DeleteEventAction(name, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Event action deleted", http.StatusOK)
}

func getEventRules(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	limit, offset, order, err := getSearchFilters(w, r)
	if err != nil {
		return
	}

	rules, err := dataprovider.GetEventRules(limit, offset, order)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, rules)
}

func renderEventRule(w http.ResponseWriter, r *http.Request, name string, status int) {
	rule, err := dataprovider.EventRuleExists(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	rule.PrepareForRendering()
	if status != http.StatusOK {
		ctx := context.WithValue(r.Context(), render.StatusCtxKey, status)
		render.JSON(w, r.WithContext(ctx), rule)
	} else {
		render.JSON(w, r, rule)
	}
}

func getEventRuleByName(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	renderEventRule(w, r, name, http.StatusOK)
}

func addEventRule(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	var rule dataprovider.EventRule
	err = render.DecodeJSON(r.Body, &rule)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	err = dataprovider.AddEventRule(&rule, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	renderEventRule(w, r, rule.Name, http.StatusCreated)
}

func updateEventRule(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}

	name := getURLParam(r, "name")
	rule, err := dataprovider.EventRuleExists(name)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	ruleID := rule.ID
	name = rule.Name
	rule.Actions = nil

	err = render.DecodeJSON(r.Body, &rule)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	rule.ID = ruleID
	rule.Name = name

	err = dataprovider.UpdateEventRule(&rule, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Event rules updated", http.StatusOK)
}

func deleteEventRule(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := getTokenClaims(r)
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	name := getURLParam(r, "name")
	err = dataprovider.DeleteEventRule(name, claims.Username, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "Event rule deleted", http.StatusOK)
}
