// Copyright (C) 2019-2023 Nicola Murino
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
	"net/http"

	"github.com/go-chi/render"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
)

type smtpTestRequest struct {
	smtp.Config
	Recipient string `json:"recipient"`
}

func testSMTPConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req smtpTestRequest
	err := render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if req.Password == redactedSecret {
		configs, err := dataprovider.GetConfigs()
		if err != nil {
			sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
			return
		}
		configs.SetNilsToEmpty()
		if err := configs.SMTP.Password.TryDecrypt(); err == nil {
			req.Password = configs.SMTP.Password.GetPayload()
		}
	}
	if err := req.SendEmail([]string{req.Recipient}, nil, "SFTPGo - Testing Email Settings",
		"It appears your SFTPGo email is setup correctly!", smtp.EmailContentTypeTextPlain); err != nil {
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	sendAPIResponse(w, r, nil, "SMTP connection OK", http.StatusOK)
}
