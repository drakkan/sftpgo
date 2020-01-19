// Package utils provides some common utility methods
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const logSender = "utils"

// IsStringInSlice searches a string in a slice and returns true if the string is found
func IsStringInSlice(obj string, list []string) bool {
	for _, v := range list {
		if v == obj {
			return true
		}
	}
	return false
}

// IsStringPrefixInSlice searches a string prefix in a slice and returns true
// if a matching prefix is found
func IsStringPrefixInSlice(obj string, list []string) bool {
	for _, v := range list {
		if strings.HasPrefix(obj, v) {
			return true
		}
	}
	return false
}

// GetTimeAsMsSinceEpoch returns unix timestamp as milliseconds from a time struct
func GetTimeAsMsSinceEpoch(t time.Time) int64 {
	return t.UnixNano() / 1000000
}

// GetTimeFromMsecSinceEpoch return a time struct from a unix timestamp with millisecond precision
func GetTimeFromMsecSinceEpoch(msec int64) time.Time {
	return time.Unix(0, msec*1000000)
}

// GetAppVersion returns VersionInfo struct
func GetAppVersion() VersionInfo {
	return versionInfo
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
	if len(s) == 0 {
		return nil
	}
	return &s
}

// EncryptData encrypts data using the given key
func EncryptData(data string) (string, error) {
	var result string
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return result, err
	}
	keyHex := hex.EncodeToString(key)
	block, err := aes.NewCipher([]byte(keyHex))
	if err != nil {
		return result, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return result, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return result, err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	result = fmt.Sprintf("$aes$%s$%x", keyHex, ciphertext)
	return result, err
}

// RemoveDecryptionKey returns encrypted data without the decryption key
func RemoveDecryptionKey(encryptData string) string {
	vals := strings.Split(encryptData, "$")
	if len(vals) == 4 {
		return fmt.Sprintf("$%v$%v", vals[1], vals[3])
	}
	return encryptData
}

// DecryptData decrypts data encrypted using EncryptData
func DecryptData(data string) (string, error) {
	var result string
	vals := strings.Split(data, "$")
	if len(vals) != 4 {
		return "", errors.New("data to decrypt is not in the correct format")
	}
	key := vals[2]
	encrypted, err := hex.DecodeString(vals[3])
	if err != nil {
		return result, err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return result, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return result, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return result, err
	}
	return string(plaintext), nil
}
