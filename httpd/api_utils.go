package httpd

import (
	"context"
	"net/http"
	"os"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
)

func sendAPIResponse(w http.ResponseWriter, r *http.Request, err error, message string, code int) {
	var errorString string
	if err != nil {
		errorString = err.Error()
	}
	resp := apiResponse{
		Error:   errorString,
		Message: message,
	}
	ctx := context.WithValue(r.Context(), render.StatusCtxKey, code)
	render.JSON(w, r.WithContext(ctx), resp)
}

func getRespStatus(err error) int {
	if _, ok := err.(*dataprovider.ValidationError); ok {
		return http.StatusBadRequest
	}
	if _, ok := err.(*dataprovider.MethodDisabledError); ok {
		return http.StatusForbidden
	}
	if _, ok := err.(*dataprovider.RecordNotFoundError); ok {
		return http.StatusNotFound
	}
	if os.IsNotExist(err) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func handleCloseConnection(w http.ResponseWriter, r *http.Request) {
	connectionID := getURLParam(r, "connectionID")
	if connectionID == "" {
		sendAPIResponse(w, r, nil, "connectionID is mandatory", http.StatusBadRequest)
		return
	}
	if common.Connections.Close(connectionID) {
		sendAPIResponse(w, r, nil, "Connection closed", http.StatusOK)
	} else {
		sendAPIResponse(w, r, nil, "Not Found", http.StatusNotFound)
	}
}
