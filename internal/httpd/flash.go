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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	flashCookieName = "message"
)

func newFlashMessage(errorStrig, i18nMessage string) flashMessage {
	return flashMessage{
		ErrorString: errorStrig,
		I18nMessage: i18nMessage,
	}
}

type flashMessage struct {
	ErrorString string `json:"error"`
	I18nMessage string `json:"message"`
}

func (m *flashMessage) getI18nError() *util.I18nError {
	if m.ErrorString == "" && m.I18nMessage == "" {
		return nil
	}
	return util.NewI18nError(
		util.NewGenericError(m.ErrorString),
		m.I18nMessage,
	)
}

func setFlashMessage(w http.ResponseWriter, r *http.Request, message flashMessage) {
	value, err := json.Marshal(message)
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    base64.URLEncoding.EncodeToString(value),
		Path:     "/",
		Expires:  time.Now().Add(60 * time.Second),
		MaxAge:   60,
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Add("Cache-Control", `no-cache="Set-Cookie"`)
}

func getFlashMessage(w http.ResponseWriter, r *http.Request) flashMessage {
	var msg flashMessage
	cookie, err := r.Cookie(flashCookieName)
	if err != nil {
		return msg
	}
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
	value, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return msg
	}
	err = json.Unmarshal(value, &msg)
	if err != nil {
		return flashMessage{}
	}
	return msg
}
