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
	"net/http"

	"github.com/go-chi/render"
	"github.com/rs/xid"
	"golang.org/x/oauth2"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

type smtpTestRequest struct {
	smtp.Config
	Recipient string `json:"recipient"`
}

func (r *smtpTestRequest) hasRedactedSecret() bool {
	return r.Password == redactedSecret || r.OAuth2.ClientSecret == redactedSecret || r.OAuth2.RefreshToken == redactedSecret
}

func testSMTPConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req smtpTestRequest
	err := render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if req.hasRedactedSecret() {
		configs, err := dataprovider.GetConfigs()
		if err != nil {
			sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
			return
		}
		configs.SetNilsToEmpty()
		if err := configs.SMTP.TryDecrypt(); err == nil {
			if req.Password == redactedSecret {
				req.Password = configs.SMTP.Password.GetPayload()
			}
			if req.OAuth2.ClientSecret == redactedSecret {
				req.OAuth2.ClientSecret = configs.SMTP.OAuth2.ClientSecret.GetPayload()
			}
			if req.OAuth2.RefreshToken == redactedSecret {
				req.OAuth2.RefreshToken = configs.SMTP.OAuth2.RefreshToken.GetPayload()
			}
		}
	}
	if req.AuthType == 3 {
		if err := req.Config.OAuth2.Validate(); err != nil {
			sendAPIResponse(w, r, err, "", http.StatusBadRequest)
			return
		}
	}
	if err := req.SendEmail([]string{req.Recipient}, nil, "SFTPGo - Testing Email Settings",
		"It appears your SFTPGo email is setup correctly!", smtp.EmailContentTypeTextPlain); err != nil {
		logger.Info(logSender, "", "unable to send test email: %v", err)
		sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
		return
	}
	sendAPIResponse(w, r, nil, "SMTP connection OK", http.StatusOK)
}

type oauth2TokenRequest struct {
	smtp.OAuth2Config
	BaseRedirectURL string `json:"base_redirect_url"`
}

func handleSMTPOAuth2TokenRequestPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req oauth2TokenRequest
	err := render.DecodeJSON(r.Body, &req)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if req.BaseRedirectURL == "" {
		sendAPIResponse(w, r, nil, "base redirect url is required", http.StatusBadRequest)
		return
	}
	if req.ClientSecret == redactedSecret {
		configs, err := dataprovider.GetConfigs()
		if err != nil {
			sendAPIResponse(w, r, err, "", http.StatusInternalServerError)
			return
		}
		configs.SetNilsToEmpty()
		if err := configs.SMTP.TryDecrypt(); err == nil {
			req.OAuth2Config.ClientSecret = configs.SMTP.OAuth2.ClientSecret.GetPayload()
		}
	}
	cfg := req.OAuth2Config.GetOAuth2()
	cfg.RedirectURL = req.BaseRedirectURL + webOAuth2RedirectPath
	clientSecret := kms.NewPlainSecret(cfg.ClientSecret)
	clientSecret.SetAdditionalData(xid.New().String())
	pendingAuth := newOAuth2PendingAuth(req.Provider, cfg.RedirectURL, cfg.ClientID, clientSecret)
	oauth2Mgr.addPendingAuth(pendingAuth)
	stateToken := createOAuth2Token(pendingAuth.State, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if stateToken == "" {
		sendAPIResponse(w, r, nil, "unable to create state token", http.StatusInternalServerError)
		return
	}
	u := cfg.AuthCodeURL(stateToken, oauth2.AccessTypeOffline)
	sendAPIResponse(w, r, nil, u, http.StatusOK)
}
