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
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/lithammer/shortuuid/v3"
	"github.com/rs/xid"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

const (
	logSender = "util"
	osWindows = "windows"
)

var (
	emailRegex = regexp.MustCompile("^(?:(?:(?:(?:[a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(?:\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|(?:(?:\\x22)(?:(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(?:\\x20|\\x09)+)?(?:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(?:(?:(?:\\x20|\\x09)*(?:\\x0d\\x0a))?(\\x20|\\x09)+)?(?:\\x22))))@(?:(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(?:(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])(?:[a-zA-Z]|\\d|-|\\.|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*(?:[a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
	// this can be set at build time
	additionalSharedDataSearchPath = ""
)

// IEC Sizes.
// kibis of bits
const (
	oneByte = 1 << (iota * 10)
	kiByte
	miByte
	giByte
	tiByte
	piByte
	eiByte
)

// SI Sizes.
const (
	iByte  = 1
	kbByte = iByte * 1000
	mByte  = kbByte * 1000
	gByte  = mByte * 1000
	tByte  = gByte * 1000
	pByte  = tByte * 1000
	eByte  = pByte * 1000
)

var bytesSizeTable = map[string]uint64{
	"b":   oneByte,
	"kib": kiByte,
	"kb":  kbByte,
	"mib": miByte,
	"mb":  mByte,
	"gib": giByte,
	"gb":  gByte,
	"tib": tiByte,
	"tb":  tByte,
	"pib": piByte,
	"pb":  pByte,
	"eib": eiByte,
	"eb":  eByte,
	// Without suffix
	"":   oneByte,
	"ki": kiByte,
	"k":  kbByte,
	"mi": miByte,
	"m":  mByte,
	"gi": giByte,
	"g":  gByte,
	"ti": tiByte,
	"t":  tByte,
	"pi": piByte,
	"p":  pByte,
	"ei": eiByte,
	"e":  eByte,
}

// Contains reports whether v is present in elems.
func Contains[T comparable](elems []T, v T) bool {
	for _, s := range elems {
		if v == s {
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
func RemoveDuplicates(obj []string, trim bool) []string {
	if len(obj) == 0 {
		return obj
	}
	seen := make(map[string]bool)
	validIdx := 0
	for _, item := range obj {
		if trim {
			item = strings.TrimSpace(item)
		}
		if !seen[item] {
			seen[item] = true
			obj[validIdx] = item
			validIdx++
		}
	}
	return obj[:validIdx]
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
	if b <= 0 {
		return strconv.FormatInt(b, 10)
	}
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := unit, 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	val := strconv.FormatFloat(float64(b)/float64(div), 'f', -1, 64)
	if unit == 1000 {
		return fmt.Sprintf("%s %cB", val, "KMGTPE"[exp])
	}
	return fmt.Sprintf("%s %ciB", val, "KMGTPE"[exp])
}

// ParseBytes parses a string representation of bytes into the number
// of bytes it represents.
//
// ParseBytes("42 MB") -> 42000000, nil
// ParseBytes("42 mib") -> 44040192, nil
//
// copied from here:
//
// https://github.com/dustin/go-humanize/blob/master/bytes.go
//
// with minor modifications
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	lastDigit := 0
	hasComma := false
	for _, r := range s {
		if !(unicode.IsDigit(r) || r == '.' || r == ',') {
			break
		}
		if r == ',' {
			hasComma = true
		}
		lastDigit++
	}

	num := s[:lastDigit]
	if hasComma {
		num = strings.Replace(num, ",", "", -1)
	}

	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, err
	}

	extra := strings.ToLower(strings.TrimSpace(s[lastDigit:]))
	if m, ok := bytesSizeTable[extra]; ok {
		f *= float64(m)
		if f >= math.MaxInt64 {
			return 0, fmt.Errorf("value too large: %v", s)
		}
		if f < 0 {
			return 0, fmt.Errorf("negative value not allowed: %v", s)
		}
		return int64(f), nil
	}

	return 0, fmt.Errorf("unhandled size name: %v", extra)
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
	return CleanPathWithBase("/", p)
}

// CleanPathWithBase returns a clean POSIX (/) absolute path to work with.
// The specified base will be used if the provided path is not absolute
func CleanPathWithBase(base, p string) string {
	p = filepath.ToSlash(p)
	if !path.IsAbs(p) {
		p = path.Join(base, p)
	}
	return path.Clean(p)
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
	if _, err := os.Stat(dirPath); errors.Is(err, fs.ErrNotExist) {
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

	for _, name := range RemoveDuplicates(cipherNames, false) {
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
func GetRealIP(r *http.Request, header string, depth int) string {
	if header == "" {
		return ""
	}
	var ipAddresses []string

	for _, h := range r.Header.Values(header) {
		for _, ipStr := range strings.Split(h, ",") {
			ipStr = strings.TrimSpace(ipStr)
			ipAddresses = append(ipAddresses, ipStr)
		}
	}

	idx := len(ipAddresses) - 1 - depth
	if idx >= 0 {
		ip := strings.TrimSpace(ipAddresses[idx])
		if ip == "" || net.ParseIP(ip) == nil {
			return ""
		}
		return ip
	}

	return ""
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

// IsEmailValid returns true if the specified email address is valid
func IsEmailValid(email string) bool {
	return emailRegex.MatchString(email)
}

// PanicOnError calls panic if err is not nil
func PanicOnError(err error) {
	if err != nil {
		panic(fmt.Errorf("unexpected error: %w", err))
	}
}
