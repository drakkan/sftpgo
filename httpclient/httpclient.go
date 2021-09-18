package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

// TLSKeyPair defines the paths for a TLS key pair
type TLSKeyPair struct {
	Cert string `json:"cert" mapstructure:"cert"`
	Key  string `json:"key" mapstructure:"key"`
}

// Header defines an HTTP header.
// If the URL is not empty, the header is added only if the
// requested URL starts with the one specified
type Header struct {
	Key   string `json:"key" mapstructure:"key"`
	Value string `json:"value" mapstructure:"value"`
	URL   string `json:"url" mapstructure:"url"`
}

// Config defines the configuration for HTTP clients.
// HTTP clients are used for executing hooks such as the ones used for
// custom actions, external authentication and pre-login user modifications
type Config struct {
	// Timeout specifies a time limit, in seconds, for a request
	Timeout float64 `json:"timeout" mapstructure:"timeout"`
	// RetryWaitMin defines the minimum waiting time between attempts in seconds
	RetryWaitMin int `json:"retry_wait_min" mapstructure:"retry_wait_min"`
	// RetryWaitMax defines the minimum waiting time between attempts in seconds
	RetryWaitMax int `json:"retry_wait_max" mapstructure:"retry_wait_max"`
	// RetryMax defines the maximum number of attempts
	RetryMax int `json:"retry_max" mapstructure:"retry_max"`
	// CACertificates defines extra CA certificates to trust.
	// The paths can be absolute or relative to the config dir.
	// Adding trusted CA certificates is a convenient way to use self-signed
	// certificates without defeating the purpose of using TLS
	CACertificates []string `json:"ca_certificates" mapstructure:"ca_certificates"`
	// Certificates defines the certificates to use for mutual TLS
	Certificates []TLSKeyPair `json:"certificates" mapstructure:"certificates"`
	// if enabled the HTTP client accepts any TLS certificate presented by
	// the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	SkipTLSVerify bool `json:"skip_tls_verify" mapstructure:"skip_tls_verify"`
	// Headers defines a list of http headers to add to each request
	Headers         []Header `json:"headers" mapstructure:"headers"`
	customTransport *http.Transport
	tlsConfig       *tls.Config
}

const logSender = "httpclient"

var httpConfig Config

// Initialize configures HTTP clients
func (c *Config) Initialize(configDir string) error {
	rootCAs, err := c.loadCACerts(configDir)
	if err != nil {
		return err
	}
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	if customTransport.TLSClientConfig != nil {
		customTransport.TLSClientConfig.RootCAs = rootCAs
	} else {
		customTransport.TLSClientConfig = &tls.Config{
			RootCAs:    rootCAs,
			NextProtos: []string{"h2", "http/1.1"},
		}
	}
	customTransport.TLSClientConfig.InsecureSkipVerify = c.SkipTLSVerify
	c.customTransport = customTransport
	c.tlsConfig = customTransport.TLSClientConfig

	err = c.loadCertificates(configDir)
	if err != nil {
		return err
	}
	var headers []Header
	for _, h := range c.Headers {
		if h.Key != "" && h.Value != "" {
			headers = append(headers, h)
		}
	}
	c.Headers = headers
	httpConfig = *c
	return nil
}

// loadCACerts returns system cert pools and try to add the configured
// CA certificates to it
func (c *Config) loadCACerts(configDir string) (*x509.CertPool, error) {
	if len(c.CACertificates) == 0 {
		return nil, nil
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}

	for _, ca := range c.CACertificates {
		if !util.IsFileInputValid(ca) {
			return nil, fmt.Errorf("unable to load invalid CA certificate: %#v", ca)
		}
		if !filepath.IsAbs(ca) {
			ca = filepath.Join(configDir, ca)
		}
		certs, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("unable to load CA certificate: %v", err)
		}
		if rootCAs.AppendCertsFromPEM(certs) {
			logger.Debug(logSender, "", "CA certificate %#v added to the trusted certificates", ca)
		} else {
			return nil, fmt.Errorf("unable to add CA certificate %#v to the trusted cetificates", ca)
		}
	}
	return rootCAs, nil
}

func (c *Config) loadCertificates(configDir string) error {
	if len(c.Certificates) == 0 {
		return nil
	}

	for _, keyPair := range c.Certificates {
		cert := keyPair.Cert
		key := keyPair.Key
		if !util.IsFileInputValid(cert) {
			return fmt.Errorf("unable to load invalid certificate: %#v", cert)
		}
		if !util.IsFileInputValid(key) {
			return fmt.Errorf("unable to load invalid key: %#v", key)
		}
		if !filepath.IsAbs(cert) {
			cert = filepath.Join(configDir, cert)
		}
		if !filepath.IsAbs(key) {
			key = filepath.Join(configDir, key)
		}
		tlsCert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return fmt.Errorf("unable to load key pair %#v, %#v: %v", cert, key, err)
		}
		logger.Debug(logSender, "", "client certificate %#v and key %#v successfully loaded", cert, key)
		c.tlsConfig.Certificates = append(c.tlsConfig.Certificates, tlsCert)
	}
	return nil
}

// GetHTTPClient returns an HTTP client with the configured parameters
func GetHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   time.Duration(httpConfig.Timeout * float64(time.Second)),
		Transport: httpConfig.customTransport,
	}
}

// GetRetraybleHTTPClient returns an HTTP client that retry a request on error.
// It uses the configured retry parameters
func GetRetraybleHTTPClient() *retryablehttp.Client {
	client := retryablehttp.NewClient()
	client.HTTPClient.Timeout = time.Duration(httpConfig.Timeout * float64(time.Second))
	client.HTTPClient.Transport.(*http.Transport).TLSClientConfig = httpConfig.tlsConfig
	client.Logger = &logger.LeveledLogger{Sender: "RetryableHTTPClient"}
	client.RetryWaitMin = time.Duration(httpConfig.RetryWaitMin) * time.Second
	client.RetryWaitMax = time.Duration(httpConfig.RetryWaitMax) * time.Second
	client.RetryMax = httpConfig.RetryMax

	return client
}

// Get issues a GET to the specified URL
func Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	addHeaders(req, url)
	client := GetHTTPClient()
	defer client.CloseIdleConnections()

	return client.Do(req)
}

// Post issues a POST to the specified URL
func Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	addHeaders(req, url)
	client := GetHTTPClient()
	defer client.CloseIdleConnections()

	return client.Do(req)
}

// RetryableGet issues a GET to the specified URL using the retryable client
func RetryableGet(url string) (*http.Response, error) {
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	addHeadersToRetryableReq(req, url)
	client := GetRetraybleHTTPClient()
	defer client.HTTPClient.CloseIdleConnections()

	return client.Do(req)
}

// RetryablePost issues a POST to the specified URL using the retryable client
func RetryablePost(url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := retryablehttp.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	addHeadersToRetryableReq(req, url)
	client := GetRetraybleHTTPClient()
	defer client.HTTPClient.CloseIdleConnections()

	return client.Do(req)
}

func addHeaders(req *http.Request, url string) {
	for idx := range httpConfig.Headers {
		h := &httpConfig.Headers[idx]
		if h.URL == "" || strings.HasPrefix(url, h.URL) {
			req.Header.Set(h.Key, h.Value)
		}
	}
}

func addHeadersToRetryableReq(req *retryablehttp.Request, url string) {
	for idx := range httpConfig.Headers {
		h := &httpConfig.Headers[idx]
		if h.URL == "" || strings.HasPrefix(url, h.URL) {
			req.Header.Set(h.Key, h.Value)
		}
	}
}
