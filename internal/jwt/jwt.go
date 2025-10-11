// Copyright (C) 2025 Nicola Murino
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

// Package jwt provides functionality for creating, parsing, and validating
// JSON Web Tokens (JWT) used in authentication and authorization workflows.
package jwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/rs/xid"
)

const (
	CookieKey = "jwt"
)

var (
	TokenCtxKey = &contextKey{"Token"}
	ErrorCtxKey = &contextKey{"Error"}
)

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "jwt context value " + k.name
}

func NewClaims(audience, ip string, duration time.Duration) *Claims {
	now := time.Now()
	claims := &Claims{}
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.NotBefore = jwt.NewNumericDate(now.Add(-10 * time.Second))
	claims.Expiry = jwt.NewNumericDate(now.Add(duration))
	claims.Audience = []string{audience, ip}
	return claims
}

type Claims struct {
	jwt.Claims
	Username                   string   `json:"username,omitempty"`
	Permissions                []string `json:"permissions,omitempty"`
	Role                       string   `json:"role,omitempty"`
	APIKeyID                   string   `json:"api_key,omitempty"`
	NodeID                     string   `json:"node_id,omitempty"`
	MustSetTwoFactorAuth       bool     `json:"2fa_required,omitempty"`
	MustChangePassword         bool     `json:"chpwd,omitempty"`
	RequiredTwoFactorProtocols []string `json:"2fa_protos,omitempty"`
	HideUserPageSections       int      `json:"hus,omitempty"`
	Ref                        string   `json:"ref,omitempty"`
}

func (c *Claims) SetIssuedAt(t time.Time) {
	c.IssuedAt = jwt.NewNumericDate(t)
}

func (c *Claims) SetNotBefore(t time.Time) {
	c.NotBefore = jwt.NewNumericDate(t)
}

func (c *Claims) SetExpiry(t time.Time) {
	c.Expiry = jwt.NewNumericDate(t)
}

func (c *Claims) HasPerm(perm string) bool {
	for _, p := range c.Permissions {
		if p == "*" || p == perm {
			return true
		}
	}
	return false
}

func (c *Claims) HasAnyAudience(audiences []string) bool {
	for _, a := range c.Audience {
		if slices.Contains(audiences, a) {
			return true
		}
	}
	return false
}

func (c *Claims) GenerateTokenResponse(signer *Signer) (TokenResponse, error) {
	token, err := signer.Sign(c)
	if err != nil {
		return TokenResponse{}, err
	}
	return c.BuildTokenResponse(token), nil
}

func (c *Claims) BuildTokenResponse(token string) TokenResponse {
	return TokenResponse{Token: token, Expiry: c.Expiry.Time().UTC().Format(time.RFC3339)}
}

type TokenResponse struct {
	Token  string `json:"access_token"`
	Expiry string `json:"expires_at"`
}

func NewSigner(algo jose.SignatureAlgorithm, key any) (*Signer, error) {
	opts := (&jose.SignerOptions{}).WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algo, Key: key}, opts)
	if err != nil {
		return nil, err
	}
	return &Signer{
		signer: signer,
		algo:   []jose.SignatureAlgorithm{algo},
		key:    key,
	}, nil
}

type Signer struct {
	algo   []jose.SignatureAlgorithm
	signer jose.Signer
	key    any
}

func (s *Signer) Sign(claims *Claims) (string, error) {
	if claims.ID == "" {
		claims.ID = xid.New().String()
	}
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(time.Now())
	}
	if claims.NotBefore == nil {
		claims.NotBefore = jwt.NewNumericDate(time.Now().Add(-10 * time.Second))
	}
	if claims.Expiry == nil {
		return "", errors.New("expiration must be set")
	}
	if len(claims.Audience) == 0 {
		return "", errors.New("audience must be set")
	}

	return jwt.Signed(s.signer).Claims(claims).Serialize()
}

func (s *Signer) Signer() jose.Signer {
	return s.signer
}

func (s *Signer) SetSigner(signer jose.Signer) {
	s.signer = signer
}

func (s *Signer) SignWithParams(claims *Claims, audience, ip string, duration time.Duration) (string, error) {
	claims.Expiry = jwt.NewNumericDate(time.Now().Add(duration))
	claims.Audience = []string{audience, ip}
	return s.Sign(claims)
}

func NewContext(ctx context.Context, claims *Claims, err error) context.Context {
	ctx = context.WithValue(ctx, TokenCtxKey, claims)
	ctx = context.WithValue(ctx, ErrorCtxKey, err)
	return ctx
}

func FromContext(ctx context.Context) (*Claims, error) {
	val := ctx.Value(TokenCtxKey)
	token, ok := val.(*Claims)
	if !ok && val != nil {
		return nil, fmt.Errorf("invalid type for TokenCtxKey: %T", val)
	}

	valErr := ctx.Value(ErrorCtxKey)
	err, ok := valErr.(error)
	if !ok && valErr != nil {
		return nil, fmt.Errorf("invalid type for ErrorCtxKey: %T", valErr)
	}
	if token == nil {
		return nil, errors.New("no token found")
	}

	return token, err
}

func Verify(s *Signer, findTokenFns ...func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token, err := VerifyRequest(s, r, findTokenFns...)
			ctx = NewContext(ctx, token, err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

func VerifyRequest(s *Signer, r *http.Request, findTokenFns ...func(r *http.Request) string) (*Claims, error) {
	var tokenString string
	for _, fn := range findTokenFns {
		tokenString = fn(r)
		if tokenString != "" {
			break
		}
	}
	if tokenString == "" {
		return nil, errors.New("no token found")
	}
	return VerifyToken(s, tokenString)
}

func VerifyToken(s *Signer, payload string) (*Claims, error) {
	return VerifyTokenWithKey(payload, s.algo, s.key)
}

func VerifyTokenWithKey(payload string, algo []jose.SignatureAlgorithm, key any) (*Claims, error) {
	token, err := jwt.ParseSigned(payload, algo)
	if err != nil {
		return nil, err
	}
	var claims Claims
	err = token.Claims(key, &claims)
	if err != nil {
		return nil, err
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Time: time.Now()}, 30*time.Second); err != nil {
		return nil, err
	}
	return &claims, nil
}

// TokenFromCookie tries to retrieve the token string from a cookie named
// "jwt".
func TokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(CookieKey)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// TokenFromHeader tries to retrieve the token string from the
// "Authorization" request header: "Authorization: BEARER T".
func TokenFromHeader(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(bearer) >= len(prefix) && strings.EqualFold(bearer[:len(prefix)], prefix) {
		return bearer[len(prefix):]
	}
	return ""
}
