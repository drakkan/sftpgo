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
