// Package api implements REST API for sftpgo.
// REST API allows to manage users and quota and to get real time reports for the active connections
// with possibility of forcibly closing a connection.
// The OpenAPI 3 schema for the exposed API can be found inside the source tree:
// https://github.com/drakkan/sftpgo/tree/master/api/schema/openapi.yaml
package api

import (
	"net/http"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

const (
	logSender             = "api"
	activeConnectionsPath = "/api/v1/connection"
	quotaScanPath         = "/api/v1/quota_scan"
	userPath              = "/api/v1/user"
	versionPath           = "/api/v1/version"
)

var (
	router       *chi.Mux
	dataProvider dataprovider.Provider
)

// HTTPDConf httpd daemon configuration
type HTTPDConf struct {
	// The port used for serving HTTP requests. 0 disable the HTTP server. Default: 8080
	BindPort int `json:"bind_port" mapstructure:"bind_port"`
	// The address to listen on. A blank value means listen on all available network interfaces. Default: "127.0.0.1"
	BindAddress string `json:"bind_address" mapstructure:"bind_address"`
}

type apiResponse struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"status"`
}

func init() {
	initializeRouter()
}

// SetDataProvider sets the data provider to use to fetch the data about users
func SetDataProvider(provider dataprovider.Provider) {
	dataProvider = provider
}

func sendAPIResponse(w http.ResponseWriter, r *http.Request, err error, message string, code int) {
	var errorString string
	if err != nil {
		errorString = err.Error()
	}
	resp := apiResponse{
		Error:      errorString,
		Message:    message,
		HTTPStatus: code,
	}
	if code != http.StatusOK {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
	}
	render.JSON(w, r, resp)
}

func getRespStatus(err error) int {
	if _, ok := err.(*dataprovider.ValidationError); ok {
		return http.StatusBadRequest
	}
	if _, ok := err.(*dataprovider.MethodDisabledError); ok {
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}
