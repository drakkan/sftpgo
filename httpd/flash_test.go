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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlashMessages(t *testing.T) {
	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/url", nil)
	require.NoError(t, err)
	message := "test message"
	setFlashMessage(rr, req, message)
	req.Header.Set("Cookie", fmt.Sprintf("%v=%v", flashCookieName, base64.URLEncoding.EncodeToString([]byte(message))))
	msg := getFlashMessage(rr, req)
	assert.Equal(t, message, msg)
	req.Header.Set("Cookie", fmt.Sprintf("%v=%v", flashCookieName, "a"))
	msg = getFlashMessage(rr, req)
	assert.Empty(t, msg)
}
