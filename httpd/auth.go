package httpd

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"golang.org/x/crypto/bcrypt"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

const (
	authenticationHeader = "WWW-Authenticate"
	authenticationRealm  = "SFTPGo Web"
	unauthResponse       = "Unauthorized"
	md5CryptPwdPrefix    = "$1$"
	apr1CryptPwdPrefix   = "$apr1$"
)

var (
	bcryptPwdPrefixes = []string{"$2a$", "$2$", "$2x$", "$2y$", "$2b$"}
)

type httpAuthProvider interface {
	getHashedPassword(username string) (string, bool)
	isEnabled() bool
}

type basicAuthProvider struct {
	Path string
	sync.RWMutex
	Info  os.FileInfo
	Users map[string]string
}

func newBasicAuthProvider(authUserFile string) (httpAuthProvider, error) {
	basicAuthProvider := basicAuthProvider{
		Path:  authUserFile,
		Info:  nil,
		Users: make(map[string]string),
	}
	return &basicAuthProvider, basicAuthProvider.loadUsers()
}

func (p *basicAuthProvider) isEnabled() bool {
	return len(p.Path) > 0
}

func (p *basicAuthProvider) isReloadNeeded(info os.FileInfo) bool {
	p.RLock()
	defer p.RUnlock()
	return p.Info == nil || p.Info.ModTime() != info.ModTime() || p.Info.Size() != info.Size()
}

func (p *basicAuthProvider) loadUsers() error {
	if !p.isEnabled() {
		return nil
	}
	info, err := os.Stat(p.Path)
	if err != nil {
		logger.Debug(logSender, "", "unable to stat basic auth users file: %v", err)
		return err
	}
	if p.isReloadNeeded(info) {
		r, err := os.Open(p.Path)
		if err != nil {
			logger.Debug(logSender, "", "unable to open basic auth users file: %v", err)
			return err
		}
		defer r.Close()
		reader := csv.NewReader(r)
		reader.Comma = ':'
		reader.Comment = '#'
		reader.TrimLeadingSpace = true
		records, err := reader.ReadAll()
		if err != nil {
			logger.Debug(logSender, "", "unable to parse basic auth users file: %v", err)
			return err
		}
		p.Lock()
		defer p.Unlock()
		p.Users = make(map[string]string)
		for _, record := range records {
			if len(record) == 2 {
				p.Users[record[0]] = record[1]
			}
		}
		logger.Debug(logSender, "", "number of users loaded for httpd basic auth: %v", len(p.Users))
		p.Info = info
	}
	return nil
}

func (p *basicAuthProvider) getHashedPassword(username string) (string, bool) {
	err := p.loadUsers()
	if err != nil {
		return "", false
	}
	p.RLock()
	defer p.RUnlock()
	pwd, ok := p.Users[username]
	return pwd, ok
}

func checkAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validateCredentials(r) {
			w.Header().Set(authenticationHeader, fmt.Sprintf("Basic realm=\"%v\"", authenticationRealm))
			if strings.HasPrefix(r.RequestURI, apiPrefix) {
				sendAPIResponse(w, r, errors.New(unauthResponse), "", http.StatusUnauthorized)
			} else {
				http.Error(w, unauthResponse, http.StatusUnauthorized)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validateCredentials(r *http.Request) bool {
	if !httpAuth.isEnabled() {
		return true
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if hashedPwd, ok := httpAuth.getHashedPassword(username); ok {
		if utils.IsStringPrefixInSlice(hashedPwd, bcryptPwdPrefixes) {
			err := bcrypt.CompareHashAndPassword([]byte(hashedPwd), []byte(password))
			return err == nil
		}
		if strings.HasPrefix(hashedPwd, md5CryptPwdPrefix) {
			crypter := md5_crypt.New()
			err := crypter.Verify(hashedPwd, []byte(password))
			return err == nil
		}
		if strings.HasPrefix(hashedPwd, apr1CryptPwdPrefix) {
			crypter := apr1_crypt.New()
			err := crypter.Verify(hashedPwd, []byte(password))
			return err == nil
		}
	}
	return false
}
