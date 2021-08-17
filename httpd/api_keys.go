package httpd

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/dataprovider"
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
	var apiKey dataprovider.APIKey
	err := render.DecodeJSON(r.Body, &apiKey)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	apiKey.ID = 0
	apiKey.KeyID = ""
	apiKey.Key = ""
	err = dataprovider.AddAPIKey(&apiKey)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	response := make(map[string]string)
	response["message"] = "API key created. This is the only time the API key is visible, please save it."
	response["key"] = apiKey.DisplayKey()
	w.Header().Add("Location", fmt.Sprintf("%v/%v", apiKeysPath, apiKey.KeyID))
	w.Header().Add("X-Object-ID", apiKey.KeyID)
	ctx := context.WithValue(r.Context(), render.StatusCtxKey, http.StatusCreated)
	render.JSON(w, r.WithContext(ctx), response)
}

func updateAPIKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	keyID := getURLParam(r, "id")
	apiKey, err := dataprovider.APIKeyExists(keyID)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	err = render.DecodeJSON(r.Body, &apiKey)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	apiKey.KeyID = keyID
	if err := dataprovider.UpdateAPIKey(&apiKey); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "API key updated", http.StatusOK)
}

func deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	keyID := getURLParam(r, "id")

	err := dataprovider.DeleteAPIKey(keyID)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, err, "API key deleted", http.StatusOK)
}
