package httpd

import (
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd/s3translate"
)

func userS3Translate(w http.ResponseWriter, r *http.Request) {
	var req s3translate.Request
	err := render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	user, err := dataprovider.CheckUserAndPass(req.Username, req.Password, ``, common.ProtocolSSH)
	if err != nil {
		if err == dataprovider.ErrInvalidCredentials {
			sendAPIResponse(w, r, err, "Access Denied", 403)
			return
		}
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}

	resp, err := req.ResolvePath(user.FsConfig)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	render.JSON(w, r, resp)
}
