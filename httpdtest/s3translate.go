package httpdtest

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/drakkan/sftpgo/httpd/s3translate"
)

type APIError struct {
	Message string `json:"message"`
	Err     string `json:"error"`
}

func (err APIError) Error() string {
	if err.Err != `` {
		return err.Err
	}
	return err.Message
}

// UpdateFolderQuotaUsage updates the folder used quota limits and checks the received HTTP Status code against expectedStatusCode.
func UsersS3Translate(request s3translate.Request, expectedStatusCode int) (s3translate.Response, error) {
	var translated s3translate.Response
	var body []byte

	folderAsJSON, _ := json.Marshal(request)
	url := buildURLRelativeToBase(`/api/v2/users-s3/translate-path`)
	resp, err := sendHTTPRequest(http.MethodPost, url, bytes.NewBuffer(folderAsJSON), "", getDefaultToken())
	if err != nil {
		return translated, err
	}
	defer resp.Body.Close()

	body, _ = getResponseBody(resp)

	if err := checkResponse(resp.StatusCode, expectedStatusCode); err != nil {
		return translated, err
	}

	if resp.StatusCode == http.StatusOK {
		if err = json.Unmarshal(body, &translated); err != nil {
			return translated, err
		}
		return translated, nil
	}

	var apiErr APIError
	if err := json.Unmarshal(body, &apiErr); err != nil {
		return translated, err
	}
	return translated, apiErr
}
