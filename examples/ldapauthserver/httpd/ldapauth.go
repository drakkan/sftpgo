package httpd

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/drakkan/sftpgo/ldapauthserver/logger"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/ssh"
)

func getSFTPGoUser(entry *ldap.Entry, username string) (SFTPGoUser, error) {
	var err error
	var user SFTPGoUser
	uid := ldapConfig.DefaultUID
	gid := ldapConfig.DefaultGID
	status := 1

	if !ldapConfig.ForceDefaultUID {
		uid, err = strconv.Atoi(entry.GetAttributeValue(ldapConfig.GetUIDNumber()))
		if err != nil {
			return user, err
		}
	}

	if !ldapConfig.ForceDefaultGID {
		uid, err = strconv.Atoi(entry.GetAttributeValue(ldapConfig.GetGIDNumber()))
		if err != nil {
			return user, err
		}
	}

	sftpgoUser := SFTPGoUser{
		Username: username,
		HomeDir:  entry.GetAttributeValue(ldapConfig.GetHomeDirectory()),
		UID:      uid,
		GID:      gid,
		Status:   status,
	}
	sftpgoUser.Permissions = make(map[string][]string)
	sftpgoUser.Permissions["/"] = []string{"*"}
	return sftpgoUser, nil
}

func checkSFTPGoUserAuth(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	var authReq externalAuthRequest
	err := render.DecodeJSON(r.Body, &authReq)
	if err != nil {
		logger.Warn(logSender, middleware.GetReqID(r.Context()), "error decoding auth request: %v", err)
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	l, err := ldap.DialURL(ldapConfig.BindURL, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: ldapConfig.InsecureSkipVerify,
		RootCAs:            rootCAs,
	}))
	if err != nil {
		logger.Warn(logSender, middleware.GetReqID(r.Context()), "error connecting to the LDAP server: %v", err)
		sendAPIResponse(w, r, err, "Error connecting to the LDAP server", http.StatusInternalServerError)
		return
	}
	defer l.Close()

	err = l.Bind(ldapConfig.BindUsername, ldapConfig.BindPassword)
	if err != nil {
		logger.Warn(logSender, middleware.GetReqID(r.Context()), "error binding to the LDAP server: %v", err)
		sendAPIResponse(w, r, err, "Error binding to the LDAP server", http.StatusInternalServerError)
		return
	}

	searchRequest := ldap.NewSearchRequest(
		ldapConfig.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		strings.Replace(ldapConfig.SearchFilter, "%s", authReq.Username, 1),
		ldapConfig.SearchBaseAttrs,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		logger.Warn(logSender, middleware.GetReqID(r.Context()), "error searching LDAP user %#v: %v", authReq.Username, err)
		sendAPIResponse(w, r, err, "Error searching LDAP user", http.StatusInternalServerError)
		return
	}

	if len(sr.Entries) != 1 {
		logger.Warn(logSender, middleware.GetReqID(r.Context()), "expected one user, found: %v", len(sr.Entries))
		sendAPIResponse(w, r, nil, fmt.Sprintf("Expected one user, found: %v", len(sr.Entries)), http.StatusNotFound)
		return
	}

	if len(authReq.PublicKey) > 0 {
		userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authReq.PublicKey))
		if err != nil {
			logger.Warn(logSender, middleware.GetReqID(r.Context()), "invalid public key for user %#v: %v", authReq.Username, err)
			sendAPIResponse(w, r, err, "Invalid public key", http.StatusBadRequest)
			return
		}
		authOk := false
		for _, k := range sr.Entries[0].GetAttributeValues(ldapConfig.GetPublicKey()) {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
			// we skip an invalid public key stored inside the LDAP server
			if err != nil {
				continue
			}
			if bytes.Equal(key.Marshal(), userKey.Marshal()) {
				authOk = true
				break
			}
		}
		if !authOk {
			logger.Warn(logSender, middleware.GetReqID(r.Context()), "public key authentication failed for user: %#v", authReq.Username)
			sendAPIResponse(w, r, nil, "public key authentication failed", http.StatusForbidden)
			return
		}
	} else {
		// bind to the LDAP server with the user dn and the given password to check the password
		userdn := sr.Entries[0].DN
		err = l.Bind(userdn, authReq.Password)
		if err != nil {
			logger.Warn(logSender, middleware.GetReqID(r.Context()), "password authentication failed for user: %#v", authReq.Username)
			sendAPIResponse(w, r, nil, "password authentication failed", http.StatusForbidden)
			return
		}
	}

	user, err := getSFTPGoUser(sr.Entries[0], authReq.Username)
	if err != nil {
		logger.Warn(logSender, middleware.GetReqID(r.Context()), "get user from LDAP entry failed for username %#v: %v",
			authReq.Username, err)
		sendAPIResponse(w, r, err, "mapping LDAP user failed", http.StatusInternalServerError)
		return
	}

	render.JSON(w, r, user)
}
