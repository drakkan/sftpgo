package httpd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/utils"
)

func TestShouldBind(t *testing.T) {
	c := Conf{
		BindPort: 10000,
	}
	require.True(t, c.ShouldBind())

	c.BindPort = 0
	require.False(t, c.ShouldBind())

	if runtime.GOOS != osWindows {
		c.BindAddress = "/absolute/path"
		require.True(t, c.ShouldBind())
	}
}

func TestGetRespStatus(t *testing.T) {
	var err error
	err = &dataprovider.MethodDisabledError{}
	respStatus := getRespStatus(err)
	assert.Equal(t, http.StatusForbidden, respStatus)
	err = fmt.Errorf("generic error")
	respStatus = getRespStatus(err)
	assert.Equal(t, http.StatusInternalServerError, respStatus)
}

func TestGCSWebInvalidFormFile(t *testing.T) {
	form := make(url.Values)
	form.Set("username", "test_username")
	form.Set("fs_provider", "2")
	req, _ := http.NewRequest(http.MethodPost, webUserPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err := req.ParseForm()
	assert.NoError(t, err)
	_, err = getFsConfigFromUserPostFields(req)
	assert.EqualError(t, err, http.ErrNotMultipart.Error())
}

func TestInvalidToken(t *testing.T) {
	admin := dataprovider.Admin{
		Username: "admin",
	}
	errFake := errors.New("fake error")
	asJSON, err := json.Marshal(admin)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPut, path.Join(adminPath, admin.Username), bytes.NewBuffer(asJSON))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("username", admin.Username)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), jwtauth.ErrorCtxKey, errFake))
	rr := httptest.NewRecorder()
	updateAdmin(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	rr = httptest.NewRecorder()
	deleteAdmin(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	adminPwd := adminPwd{
		CurrentPassword: "old",
		NewPassword:     "new",
	}
	asJSON, err = json.Marshal(adminPwd)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, "", bytes.NewBuffer(asJSON))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), jwtauth.ErrorCtxKey, errFake))
	rr = httptest.NewRecorder()
	changeAdminPassword(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	adm := getAdminFromToken(req)
	assert.Empty(t, adm.Username)
}

func TestUpdateWebAdminInvalidClaims(t *testing.T) {
	server := httpdServer{}
	server.initializeRouter()

	rr := httptest.NewRecorder()
	admin := dataprovider.Admin{
		Username: "",
		Password: "password",
	}
	c := jwtTokenClaims{
		Username:    admin.Username,
		Permissions: admin.Permissions,
		Signature:   admin.GetSignature(),
	}
	token, err := c.createTokenResponse(server.tokenAuth)
	assert.NoError(t, err)

	form := make(url.Values)
	form.Set("status", "1")
	req, _ := http.NewRequest(http.MethodPost, path.Join(webAdminPath, "admin"), bytes.NewBuffer([]byte(form.Encode())))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("username", "admin")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	handleWebUpdateAdminPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")
}

func TestCreateTokenError(t *testing.T) {
	server := httpdServer{
		tokenAuth: jwtauth.New("PS256", utils.GenerateRandomBytes(32), nil),
	}
	rr := httptest.NewRecorder()
	admin := dataprovider.Admin{
		Username: "admin",
		Password: "password",
	}
	req, _ := http.NewRequest(http.MethodGet, tokenPath, nil)

	server.checkAddrAndSendToken(rr, req, admin)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	rr = httptest.NewRecorder()
	form := make(url.Values)
	form.Set("username", admin.Username)
	form.Set("password", admin.Password)
	req, _ = http.NewRequest(http.MethodPost, webLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.handleWebLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	// req with no content type
	req, _ = http.NewRequest(http.MethodPost, webLoginPath, nil)
	rr = httptest.NewRecorder()
	server.handleWebLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	// req with no POST body
	req, _ = http.NewRequest(http.MethodGet, webLoginPath+"?a=a%C3%AO%GG", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	req, _ = http.NewRequest(http.MethodGet, webLoginPath+"?a=a%C3%A1%G2", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handleWebAdminChangePwdPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	req, _ = http.NewRequest(http.MethodGet, webLoginPath+"?a=a%C3%A2%G3", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err := getAdminFromPostFields(req)
	assert.Error(t, err)
}

func TestJWTTokenValidation(t *testing.T) {
	tokenAuth := jwtauth.New("HS256", utils.GenerateRandomBytes(32), nil)
	claims := make(map[string]interface{})
	claims["username"] = "admin"
	claims[jwt.ExpirationKey] = time.Now().UTC().Add(-1 * time.Hour)
	token, _, err := tokenAuth.Encode(claims)
	assert.NoError(t, err)

	r := GetHTTPRouter()
	fn := jwtAuthenticator(r)
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, userPath, nil)
	ctx := jwtauth.NewContext(req.Context(), token, nil)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	fn = jwtAuthenticatorWeb(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webUserPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)

	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusFound, rr.Code)

	errTest := errors.New("test error")
	permFn := checkPerm(dataprovider.PermAdminAny)
	fn = permFn(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, userPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, errTest)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	permFn = checkPerm(dataprovider.PermAdminAny)
	fn = permFn(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webUserPath, nil)
	req.RequestURI = webUserPath
	ctx = jwtauth.NewContext(req.Context(), token, errTest)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAdminAllowListConnAddr(t *testing.T) {
	server := httpdServer{}
	admin := dataprovider.Admin{
		Filters: dataprovider.AdminFilters{
			AllowList: []string{"192.168.1.0/24"},
		},
	}
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, tokenPath, nil)
	ctx := context.WithValue(req.Context(), connAddrKey, "127.0.0.1:4567")
	req.RemoteAddr = "192.168.1.16:1234"
	server.checkAddrAndSendToken(rr, req.WithContext(ctx), admin)
	assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
}

func TestUpdateContextFromCookie(t *testing.T) {
	server := httpdServer{
		tokenAuth: jwtauth.New("HS256", utils.GenerateRandomBytes(32), nil),
	}
	req, _ := http.NewRequest(http.MethodGet, tokenPath, nil)
	claims := make(map[string]interface{})
	claims["a"] = "b"
	token, _, err := server.tokenAuth.Encode(claims)
	assert.NoError(t, err)

	ctx := jwtauth.NewContext(req.Context(), token, nil)
	server.updateContextFromCookie(req.WithContext(ctx))
}

func TestCookieExpiration(t *testing.T) {
	server := httpdServer{
		tokenAuth: jwtauth.New("HS256", utils.GenerateRandomBytes(32), nil),
	}
	err := errors.New("test error")
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, tokenPath, nil)
	ctx := jwtauth.NewContext(req.Context(), nil, err)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie := rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	claims := make(map[string]interface{})
	claims["a"] = "b"
	token, _, err := server.tokenAuth.Encode(claims)
	assert.NoError(t, err)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	admin := dataprovider.Admin{
		Username:    "newtestadmin",
		Password:    "password",
		Permissions: []string{dataprovider.PermAdminAny},
	}
	claims = make(map[string]interface{})
	claims[claimUsernameKey] = admin.Username
	claims[claimPermissionsKey] = admin.Permissions
	claims[jwt.SubjectKey] = admin.GetSignature()
	claims[jwt.ExpirationKey] = time.Now().Add(1 * time.Minute)
	token, _, err = server.tokenAuth.Encode(claims)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	admin.Status = 0
	err = dataprovider.AddAdmin(&admin)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	admin.Status = 1
	admin.Filters.AllowList = []string{"172.16.1.0/24"}
	err = dataprovider.UpdateAdmin(&admin)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	admin, err = dataprovider.AdminExists(admin.Username)
	assert.NoError(t, err)
	claims = make(map[string]interface{})
	claims[claimUsernameKey] = admin.Username
	claims[claimPermissionsKey] = admin.Permissions
	claims[jwt.SubjectKey] = admin.GetSignature()
	claims[jwt.ExpirationKey] = time.Now().Add(1 * time.Minute)
	token, _, err = server.tokenAuth.Encode(claims)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	req.RemoteAddr = "192.168.8.1:1234"
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	req.RemoteAddr = "172.16.1.2:1234"
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	ctx = context.WithValue(ctx, connAddrKey, "10.9.9.9")
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	req.RemoteAddr = "172.16.1.12:4567"
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.True(t, strings.HasPrefix(cookie, "jwt="))

	err = dataprovider.DeleteAdmin(admin.Username)
	assert.NoError(t, err)
}

func TestGetURLParam(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, adminPwdPath, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("val", "testuser%C3%A0")
	rctx.URLParams.Add("inval", "testuser%C3%AO%GG")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	escaped := getURLParam(req, "val")
	assert.Equal(t, "testuserà", escaped)
	escaped = getURLParam(req, "inval")
	assert.Equal(t, "testuser%C3%AO%GG", escaped)
}

func TestChangePwdValidationErrors(t *testing.T) {
	err := doChangeAdminPassword(nil, "", "", "")
	require.Error(t, err)
	err = doChangeAdminPassword(nil, "a", "b", "c")
	require.Error(t, err)
	err = doChangeAdminPassword(nil, "a", "a", "a")
	require.Error(t, err)

	req, _ := http.NewRequest(http.MethodPut, adminPwdPath, nil)
	err = doChangeAdminPassword(req, "currentpwd", "newpwd", "newpwd")
	assert.Error(t, err)
}

func TestRenderUnexistingFolder(t *testing.T) {
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, folderPath, nil)
	renderFolder(rr, req, "path not mapped")
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestCloseConnectionHandler(t *testing.T) {
	req, _ := http.NewRequest(http.MethodDelete, activeConnectionsPath+"/connectionID", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("connectionID", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	handleCloseConnection(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRenderInvalidTemplate(t *testing.T) {
	tmpl, err := template.New("test").Parse("{{.Count}}")
	if assert.NoError(t, err) {
		templates["no_match"] = tmpl
		rw := httptest.NewRecorder()
		renderTemplate(rw, "no_match", map[string]string{})
		assert.Equal(t, http.StatusInternalServerError, rw.Code)
	}
}

func TestQuotaScanInvalidFs(t *testing.T) {
	user := dataprovider.User{
		Username: "test",
		HomeDir:  os.TempDir(),
		FsConfig: dataprovider.Filesystem{
			Provider: dataprovider.S3FilesystemProvider,
		},
	}
	common.QuotaScans.AddUserQuotaScan(user.Username)
	err := doQuotaScan(user)
	assert.Error(t, err)
}
