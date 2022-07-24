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
	"encoding/base64"
	"net/http"
	"time"
)

const (
	flashCookieName = "message"
)

func setFlashMessage(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    base64.URLEncoding.EncodeToString([]byte(value)),
		Path:     "/",
		Expires:  time.Now().Add(60 * time.Second),
		MaxAge:   60,
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func getFlashMessage(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie(flashCookieName)
	if err != nil {
		return ""
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
	message, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return ""
	}
	return string(message)
}
