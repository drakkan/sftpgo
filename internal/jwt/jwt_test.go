package jwt

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/util"
)

type failingJoseSigner struct{}

func (s *failingJoseSigner) Sign(payload []byte) (*jose.JSONWebSignature, error) {
	return nil, errors.New("sign test error")
}

func (s *failingJoseSigner) Options() jose.SignerOptions {
	return jose.SignerOptions{}
}

func TestJWTToken(t *testing.T) {
	s, err := NewSigner(jose.HS256, util.GenerateRandomBytes(32))
	require.NoError(t, err)
	username := util.GenerateUniqueID()
	claims := Claims{
		Username: username,
		Claims: jwt.Claims{
			Audience:  jwt.Audience{"test"},
			Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token, err := s.Sign(&claims)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	parsed, err := VerifyToken(s, token)
	require.NoError(t, err)
	require.Equal(t, username, parsed.Username)

	ja1, err := NewSigner(jose.HS256, util.GenerateRandomBytes(32))
	require.NoError(t, err)

	token, err = ja1.Sign(&claims)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	_, err = VerifyToken(s, token)
	require.Error(t, err)
	_, err = VerifyToken(ja1, token)
	require.NoError(t, err)
}

func TestClaims(t *testing.T) {
	claims := NewClaims(util.GenerateUniqueID(), "", 10*time.Minute)
	s, err := NewSigner(jose.HS256, util.GenerateRandomBytes(32))
	require.NoError(t, err)
	token, err := s.Sign(claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotNil(t, claims.Expiry)
	assert.NotNil(t, claims.IssuedAt)
	assert.NotNil(t, claims.NotBefore)

	claims = &Claims{
		Permissions: []string{"myperm"},
	}
	claims.SetExpiry(time.Now().Add(1 * time.Minute))
	claims.Audience = []string{"testaudience"}
	_, err = s.Sign(claims)
	assert.NoError(t, err)
	assert.NotNil(t, claims.IssuedAt)
	assert.NotNil(t, claims.NotBefore)
	assert.True(t, claims.HasAnyAudience([]string{util.GenerateUniqueID(), util.GenerateUniqueID(), "testaudience"}))
	assert.False(t, claims.HasAnyAudience([]string{util.GenerateUniqueID()}))
	assert.True(t, claims.HasPerm("myperm"))
	assert.False(t, claims.HasPerm(util.GenerateUniqueID()))
	resp, err := claims.GenerateTokenResponse(s)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, claims.Expiry.Time().UTC().Format(time.RFC3339), resp.Expiry)
	claims.SetIssuedAt(time.Now())
	claims.SetNotBefore(time.Now().Add(10 * time.Minute))
	token, err = s.SignWithParams(claims, util.GenerateUniqueID(), "127.0.0.1", time.Minute)
	assert.NoError(t, err)
	_, err = VerifyToken(s, token)
	assert.ErrorContains(t, err, "nbf")
	claims = &Claims{}
	_, err = s.Sign(claims)
	assert.ErrorContains(t, err, "expiration must be set")
	claims.SetExpiry(time.Now())
	_, err = s.Sign(claims)
	assert.ErrorContains(t, err, "audience must be set")
	claims = &Claims{}
	_, err = s.SignWithParams(claims, util.GenerateUniqueID(), "", time.Minute)
	assert.NoError(t, err)
}

func TestClaimsPermissions(t *testing.T) {
	c := Claims{
		Permissions: []string{"*"},
	}
	assert.True(t, c.HasPerm(util.GenerateUniqueID()))
	c.Permissions = []string{"list"}
	assert.False(t, c.HasPerm(util.GenerateUniqueID()))
	assert.True(t, c.HasPerm("list"))
}

func TestErrors(t *testing.T) {
	s, err := NewSigner(jose.HS256, util.GenerateRandomBytes(32))
	require.NoError(t, err)
	_, err = VerifyToken(s, util.GenerateUniqueID())
	assert.Error(t, err)
	claims := &Claims{}
	claims.SetExpiry(time.Now().Add(-1 * time.Minute))
	token, err := jwt.Signed(s.Signer()).Claims(claims).Serialize()
	assert.NoError(t, err)
	_, err = VerifyToken(s, token)
	assert.ErrorContains(t, err, "exp")
	claims.SetExpiry(time.Now().Add(2 * time.Minute))
	claims.SetIssuedAt(time.Now().Add(1 * time.Minute))
	token, err = jwt.Signed(s.Signer()).Claims(claims).Serialize()
	assert.NoError(t, err)
	_, err = VerifyToken(s, token)
	assert.ErrorContains(t, err, "iat")
	claims.SetIssuedAt(time.Now())
	claims.SetNotBefore(time.Now().Add(1 * time.Minute))
	token, err = jwt.Signed(s.Signer()).Claims(claims).Serialize()
	assert.NoError(t, err)
	_, err = VerifyToken(s, token)
	assert.ErrorContains(t, err, "nbf")

	s.SetSigner(&failingJoseSigner{})
	claims = NewClaims(util.GenerateUniqueID(), "", time.Minute)
	_, err = s.Sign(claims)
	assert.Error(t, err)
	_, err = claims.GenerateTokenResponse(s)
	assert.Error(t, err)
	// Wrong algorithm
	_, err = NewSigner("PS256", util.GenerateRandomBytes(32))
	assert.Error(t, err)
}

func TestTokenFromRequest(t *testing.T) {
	claims := NewClaims(util.GenerateUniqueID(), "", 10*time.Minute)
	s, err := NewSigner(jose.HS256, util.GenerateRandomBytes(32))
	require.NoError(t, err)
	token, err := s.Sign(claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%s", token))
	cookie := TokenFromCookie(req)
	assert.Equal(t, token, cookie)
	req, err = http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	_, err = VerifyRequest(s, req, TokenFromHeader)
	assert.NoError(t, err)
	req.Header.Set("Authorization", token)
	assert.Empty(t, TokenFromHeader(req))
	assert.Empty(t, TokenFromCookie(req))
	_, err = VerifyRequest(s, req, TokenFromCookie)
	assert.ErrorContains(t, err, "no token found")
}

func TestContext(t *testing.T) {
	claims := &Claims{
		Username: util.GenerateUniqueID(),
	}
	s, err := NewSigner(jose.HS256, util.GenerateRandomBytes(32))
	require.NoError(t, err)
	token, err := s.SignWithParams(claims, util.GenerateUniqueID(), "", time.Minute)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	h := Verify(s, TokenFromHeader)
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := FromContext(r.Context())
		assert.Nil(t, err)
		assert.Equal(t, claims.Username, token.Username)
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	_, err = FromContext(context.Background())
	assert.ErrorContains(t, err, "no token found")

	ctx := NewContext(context.Background(), &Claims{}, fs.ErrClosed)
	_, err = FromContext(ctx)
	assert.Equal(t, fs.ErrClosed, err)

	ctx = context.WithValue(context.Background(), TokenCtxKey, "1")
	_, err = FromContext(ctx)
	assert.ErrorContains(t, err, "invalid type for TokenCtxKey")

	ctx = context.WithValue(context.Background(), ErrorCtxKey, 2)
	_, err = FromContext(ctx)
	assert.ErrorContains(t, err, "invalid type for ErrorCtxKey")
	claims = NewClaims(util.GenerateUniqueID(), "127.1.1.1", time.Minute)
	_, err = s.Sign(claims)
	require.NoError(t, err)
	ctx = context.WithValue(context.Background(), TokenCtxKey, claims)
	claimsFromContext, err := FromContext(ctx)
	assert.NoError(t, err)
	assert.Equal(t, claims, claimsFromContext)

	assert.Equal(t, "jwt context value Token", TokenCtxKey.String())
}
