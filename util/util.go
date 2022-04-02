// Package util provides some common utility methods
package util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lithammer/shortuuid/v3"
	"github.com/rs/xid"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/logger"
)

const (
	logSender = "util"
	osWindows = "windows"
)

var (
	xForwardedFor  = http.CanonicalHeaderKey("X-Forwarded-For")
	xRealIP        = http.CanonicalHeaderKey("X-Real-IP")
	cfConnectingIP = http.CanonicalHeaderKey("CF-Connecting-IP")
	trueClientIP   = http.CanonicalHeaderKey("True-Client-IP")
)

// IsStringInSlice searches a string in a slice and returns true if the string is found
func IsStringInSlice(obj string, list []string) bool {
	for i := 0; i < len(list); i++ {
		if list[i] == obj {
			return true
		}
	}
	return false
}

// IsStringPrefixInSlice searches a string prefix in a slice and returns true
// if a matching prefix is found
func IsStringPrefixInSlice(obj string, list []string) bool {
	for i := 0; i < len(list); i++ {
		if strings.HasPrefix(obj, list[i]) {
			return true
		}
	}
	return false
}

// RemoveDuplicates returns a new slice removing any duplicate element from the initial one
func RemoveDuplicates(obj []string) []string {
	if len(obj) == 0 {
		return obj
	}
	result := make([]string, 0, len(obj))
	seen := make(map[string]bool)
	for _, item := range obj {
		if _, ok := seen[item]; !ok {
			result = append(result, item)
		}
		seen[item] = true
	}
	return result
}

// GetTimeAsMsSinceEpoch returns unix timestamp as milliseconds from a time struct
func GetTimeAsMsSinceEpoch(t time.Time) int64 {
	return t.UnixMilli()
}

// GetTimeFromMsecSinceEpoch return a time struct from a unix timestamp with millisecond precision
func GetTimeFromMsecSinceEpoch(msec int64) time.Time {
	return time.Unix(0, msec*1000000)
}

// GetDurationAsString returns a string representation for a time.Duration
func GetDurationAsString(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// ByteCountSI returns humanized size in SI (decimal) format
func ByteCountSI(b int64) string {
	return byteCount(b, 1000)
}

// ByteCountIEC returns humanized size in IEC (binary) format
func ByteCountIEC(b int64) string {
	return byteCount(b, 1024)
}

func byteCount(b int64, unit int64) string {
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := unit, 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	if unit == 1000 {
		return fmt.Sprintf("%.1f %cB",
			float64(b)/float64(div), "KMGTPE"[exp])
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(b)/float64(div), "KMGTPE"[exp])
}

// GetIPFromRemoteAddress returns the IP from the remote address.
// If the given remote address cannot be parsed it will be returned unchanged
func GetIPFromRemoteAddress(remoteAddress string) string {
	ip, _, err := net.SplitHostPort(remoteAddress)
	if err == nil {
		return ip
	}
	return remoteAddress
}

// NilIfEmpty returns nil if the input string is empty
func NilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// GetStringFromPointer returns the string value or empty if nil
func GetStringFromPointer(val *string) string {
	if val == nil {
		return ""
	}
	return *val
}

// GetIntFromPointer returns the int value or zero
func GetIntFromPointer(val *int64) int64 {
	if val == nil {
		return 0
	}
	return *val
}

// GetTimeFromPointer returns the time value or now
func GetTimeFromPointer(val *time.Time) time.Time {
	if val == nil {
		return time.Now()
	}
	return *val
}

// GenerateRSAKeys generate rsa private and public keys and write the
// private key to specified file and the public key to the specified
// file adding the .pub suffix
func GenerateRSAKeys(file string) error {
	if err := createDirPathIfMissing(file, 0700); err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	o, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer o.Close()

	priv := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	if err := pem.Encode(o, priv); err != nil {
		return err
	}

	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	return os.WriteFile(file+".pub", ssh.MarshalAuthorizedKey(pub), 0600)
}

// GenerateECDSAKeys generate ecdsa private and public keys and write the
// private key to specified file and the public key to the specified
// file adding the .pub suffix
func GenerateECDSAKeys(file string) error {
	if err := createDirPathIfMissing(file, 0700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	priv := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	o, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer o.Close()

	if err := pem.Encode(o, priv); err != nil {
		return err
	}

	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	return os.WriteFile(file+".pub", ssh.MarshalAuthorizedKey(pub), 0600)
}

// GenerateEd25519Keys generate ed25519 private and public keys and write the
// private key to specified file and the public key to the specified
// file adding the .pub suffix
func GenerateEd25519Keys(file string) error {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	priv := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	o, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer o.Close()

	if err := pem.Encode(o, priv); err != nil {
		return err
	}
	pub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return err
	}
	return os.WriteFile(file+".pub", ssh.MarshalAuthorizedKey(pub), 0600)
}

// GetDirsForVirtualPath returns all the directory for the given path in reverse order
// for example if the path is: /1/2/3/4 it returns:
// [ "/1/2/3/4", "/1/2/3", "/1/2", "/1", "/" ]
func GetDirsForVirtualPath(virtualPath string) []string {
	if virtualPath == "" || virtualPath == "." {
		virtualPath = "/"
	} else {
		if !path.IsAbs(virtualPath) {
			virtualPath = CleanPath(virtualPath)
		}
	}
	dirsForPath := []string{virtualPath}
	for {
		if virtualPath == "/" {
			break
		}
		virtualPath = path.Dir(virtualPath)
		dirsForPath = append(dirsForPath, virtualPath)
	}
	return dirsForPath
}

// CleanPath returns a clean POSIX (/) absolute path to work with
func CleanPath(p string) string {
	p = filepath.ToSlash(p)
	if !path.IsAbs(p) {
		p = "/" + p
	}
	return path.Clean(p)
}

// LoadTemplate parses the given template paths.
// It behaves like template.Must but it writes a log before exiting.
// You can optionally provide a base template (e.g. to define some custom functions)
func LoadTemplate(base *template.Template, paths ...string) *template.Template {
	var t *template.Template
	var err error

	if base != nil {
		base, err = base.Clone()
		if err == nil {
			t, err = base.ParseFiles(paths...)
		}
	} else {
		t, err = template.ParseFiles(paths...)
	}

	if err != nil {
		logger.ErrorToConsole("error loading required template: %v", err)
		logger.Error(logSender, "", "error loading required template: %v", err)
		panic(err)
	}
	return t
}

// IsFileInputValid returns true this is a valid file name.
// This method must be used before joining a file name, generally provided as
// user input, with a directory
func IsFileInputValid(fileInput string) bool {
	cleanInput := filepath.Clean(fileInput)
	if cleanInput == "." || cleanInput == ".." {
		return false
	}
	return true
}

// CleanDirInput sanitizes user input for directories.
// On Windows it removes any trailing `"`.
// We try to help windows users that set an invalid path such as "C:\ProgramData\SFTPGO\".
// This will only help if the invalid path is the last argument, for example in this command:
// sftpgo.exe serve -c "C:\ProgramData\SFTPGO\" -l "sftpgo.log"
// the -l flag will be ignored and the -c flag will get the value `C:\ProgramData\SFTPGO" -l sftpgo.log`
// since the backslash after SFTPGO escape the double quote. This is definitely a bad user input
func CleanDirInput(dirInput string) string {
	if runtime.GOOS == osWindows {
		for strings.HasSuffix(dirInput, "\"") {
			dirInput = strings.TrimSuffix(dirInput, "\"")
		}
	}
	return filepath.Clean(dirInput)
}

func createDirPathIfMissing(file string, perm os.FileMode) error {
	dirPath := filepath.Dir(file)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err = os.MkdirAll(dirPath, perm)
		if err != nil {
			return err
		}
	}
	return nil
}

// GenerateRandomBytes generates the secret to use for JWT auth
func GenerateRandomBytes(length int) []byte {
	b := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, b)
	if err == nil {
		return b
	}

	b = xid.New().Bytes()
	for len(b) < length {
		b = append(b, xid.New().Bytes()...)
	}

	return b[:length]
}

// GenerateUniqueID retuens an unique ID
func GenerateUniqueID() string {
	u, err := uuid.NewRandom()
	if err != nil {
		return xid.New().String()
	}
	return shortuuid.DefaultEncoder.Encode(u)
}

// HTTPListenAndServe is a wrapper for ListenAndServe that support both tcp
// and Unix-domain sockets
func HTTPListenAndServe(srv *http.Server, address string, port int, isTLS bool, logSender string) error {
	var listener net.Listener
	var err error

	if filepath.IsAbs(address) && runtime.GOOS != osWindows {
		if !IsFileInputValid(address) {
			return fmt.Errorf("invalid socket address %#v", address)
		}
		err = createDirPathIfMissing(address, os.ModePerm)
		if err != nil {
			logger.ErrorToConsole("error creating Unix-domain socket parent dir: %v", err)
			logger.Error(logSender, "", "error creating Unix-domain socket parent dir: %v", err)
		}
		os.Remove(address)
		listener, err = newListener("unix", address, srv.ReadTimeout, srv.WriteTimeout)
	} else {
		CheckTCP4Port(port)
		listener, err = newListener("tcp", fmt.Sprintf("%s:%d", address, port), srv.ReadTimeout, srv.WriteTimeout)
	}
	if err != nil {
		return err
	}

	logger.Info(logSender, "", "server listener registered, address: %v TLS enabled: %v", listener.Addr().String(), isTLS)

	defer listener.Close()

	if isTLS {
		return srv.ServeTLS(listener, "", "")
	}
	return srv.Serve(listener)
}

// GetTLSCiphersFromNames returns the TLS ciphers from the specified names
func GetTLSCiphersFromNames(cipherNames []string) []uint16 {
	var ciphers []uint16

	for _, name := range RemoveDuplicates(cipherNames) {
		for _, c := range tls.CipherSuites() {
			if c.Name == strings.TrimSpace(name) {
				ciphers = append(ciphers, c.ID)
			}
		}
	}

	return ciphers
}

// EncodeTLSCertToPem returns the specified certificate PEM encoded.
// This can be verified using openssl x509 -in cert.crt  -text -noout
func EncodeTLSCertToPem(tlsCert *x509.Certificate) (string, error) {
	if len(tlsCert.Raw) == 0 {
		return "", errors.New("invalid x509 certificate, no der contents")
	}
	publicKeyBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tlsCert.Raw,
	}
	return string(pem.EncodeToMemory(&publicKeyBlock)), nil
}

// CheckTCP4Port quits the app if bind on the given IPv4 port fails.
// This is a ugly hack to avoid to bind on an already used port.
// It is required on Windows only. Upstream does not consider this
// behaviour a bug:
// https://github.com/golang/go/issues/45150
func CheckTCP4Port(port int) {
	if runtime.GOOS != osWindows {
		return
	}
	listener, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.ErrorToConsole("unable to bind on tcp4 address: %v", err)
		logger.Error(logSender, "", "unable to bind on tcp4 address: %v", err)
		os.Exit(1)
	}
	listener.Close()
}

// IsByteArrayEmpty return true if the byte array is empty or a new line
func IsByteArrayEmpty(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if bytes.Equal(b, []byte("\n")) {
		return true
	}
	if bytes.Equal(b, []byte("\r\n")) {
		return true
	}
	return false
}

// GetSSHPublicKeyAsString returns an SSH public key serialized as string
func GetSSHPublicKeyAsString(pubKey []byte) (string, error) {
	if len(pubKey) == 0 {
		return "", nil
	}
	k, err := ssh.ParsePublicKey(pubKey)
	if err != nil {
		return "", err
	}
	return string(ssh.MarshalAuthorizedKey(k)), nil
}

// GetRealIP returns the ip address as result of parsing either the
// X-Real-IP header or the X-Forwarded-For header
func GetRealIP(r *http.Request) string {
	var ip string

	if clientIP := r.Header.Get(trueClientIP); clientIP != "" {
		ip = clientIP
	} else if xrip := r.Header.Get(xRealIP); xrip != "" {
		ip = xrip
	} else if clientIP := r.Header.Get(cfConnectingIP); clientIP != "" {
		ip = clientIP
	} else if xff := r.Header.Get(xForwardedFor); xff != "" {
		i := strings.Index(xff, ",")
		if i == -1 {
			i = len(xff)
		}
		ip = strings.TrimSpace(xff[:i])
	}
	if ip == "" || net.ParseIP(ip) == nil {
		return ""
	}

	return ip
}

// GetHTTPLocalAddress returns the local address for an http.Request
// or empty if it cannot be determined
func GetHTTPLocalAddress(r *http.Request) string {
	if r == nil {
		return ""
	}
	localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if ok {
		return localAddr.String()
	}
	return ""
}

// ParseAllowedIPAndRanges returns a list of functions that allow to find if an
// IP is equal or is contained within the allowed list
func ParseAllowedIPAndRanges(allowed []string) ([]func(net.IP) bool, error) {
	res := make([]func(net.IP) bool, len(allowed))
	for i, allowFrom := range allowed {
		if strings.LastIndex(allowFrom, "/") > 0 {
			_, ipRange, err := net.ParseCIDR(allowFrom)
			if err != nil {
				return nil, fmt.Errorf("given string %q is not a valid IP range: %v", allowFrom, err)
			}

			res[i] = ipRange.Contains
		} else {
			allowed := net.ParseIP(allowFrom)
			if allowed == nil {
				return nil, fmt.Errorf("given string %q is not a valid IP address", allowFrom)
			}

			res[i] = allowed.Equal
		}
	}

	return res, nil
}

// GetRedactedURL returns the url redacting the password if any
func GetRedactedURL(rawurl string) string {
	if !strings.HasPrefix(rawurl, "http") {
		return rawurl
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	return u.Redacted()
}

// PrependFileInfo prepends a file info to a slice in an efficient way.
// We, optimistically, assume that the slice has enough capacity
func PrependFileInfo(files []os.FileInfo, info os.FileInfo) []os.FileInfo {
	files = append(files, nil)
	copy(files[1:], files)
	files[0] = info
	return files
}

// GetTLSVersion returns the TLS version for integer:
// - 12 means TLS 1.2
// - 13 means TLS 1.3
// default is TLS 1.2
func GetTLSVersion(val int) uint16 {
	switch val {
	case 13:
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}
