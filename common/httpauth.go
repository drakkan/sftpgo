package common

import (
	"encoding/csv"
	"os"
	"strings"
	"sync"

	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"golang.org/x/crypto/bcrypt"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

const (
	// HTTPAuthenticationHeader defines the HTTP authentication
	HTTPAuthenticationHeader = "WWW-Authenticate"
	md5CryptPwdPrefix        = "$1$"
	apr1CryptPwdPrefix       = "$apr1$"
)

var (
	bcryptPwdPrefixes = []string{"$2a$", "$2$", "$2x$", "$2y$", "$2b$"}
)

// HTTPAuthProvider defines the interface for HTTP auth providers
type HTTPAuthProvider interface {
	ValidateCredentials(username, password string) bool
	IsEnabled() bool
}

type basicAuthProvider struct {
	Path string
	sync.RWMutex
	Info  os.FileInfo
	Users map[string]string
}

// NewBasicAuthProvider returns an HTTPAuthProvider implementing Basic Auth
func NewBasicAuthProvider(authUserFile string) (HTTPAuthProvider, error) {
	basicAuthProvider := basicAuthProvider{
		Path:  authUserFile,
		Info:  nil,
		Users: make(map[string]string),
	}
	return &basicAuthProvider, basicAuthProvider.loadUsers()
}

func (p *basicAuthProvider) IsEnabled() bool {
	return p.Path != ""
}

func (p *basicAuthProvider) isReloadNeeded(info os.FileInfo) bool {
	p.RLock()
	defer p.RUnlock()

	return p.Info == nil || p.Info.ModTime() != info.ModTime() || p.Info.Size() != info.Size()
}

func (p *basicAuthProvider) loadUsers() error {
	if !p.IsEnabled() {
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

// ValidateCredentials returns true if the credentials are valid
func (p *basicAuthProvider) ValidateCredentials(username, password string) bool {
	if hashedPwd, ok := p.getHashedPassword(username); ok {
		if util.IsStringPrefixInSlice(hashedPwd, bcryptPwdPrefixes) {
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
