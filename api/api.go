package api

import (
	"net/http"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

const (
	logSender             = "api"
	activeConnectionsPath = "/api/v1/sftp_connection"
	quotaScanPath         = "/api/v1/quota_scan"
	userPath              = "/api/v1/user"
)

var (
	router       *chi.Mux
	dataProvider dataprovider.Provider
)

// HTTPDConf httpd daemon configuration
type HTTPDConf struct {
	BindPort    int    `json:"bind_port"`
	BindAddress string `json:"bind_address"`
}

type apiResponse struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"status"`
}

func init() {
	initializeRouter()
}

// SetDataProvider sets the data provider
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
