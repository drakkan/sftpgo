package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// dataproviderAvailability is the metric that reports the availability for the configured data provider
	dataproviderAvailability = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sftpgo_dataprovider_availability",
		Help: "Availability for the configured data provider, 1 means OK, 0 KO",
	})

	// activeConnections is the metric that reports the total number of active connections
	activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sftpgo_active_connections",
		Help: "Total number of logged in users",
	})

	// totalUploads is the metric that reports the total number of uploads
	totalUploads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_uploads_total",
		Help: "The total number of uploads",
	})

	// totalDownloads is the metric that reports the total number of downloads
	totalDownloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_downloads_total",
		Help: "The total number of downloads",
	})

	// totalUploadErrors is the metric that reports the total number of upload errors
	totalUploadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_upload_errors_total",
		Help: "The total number of upload errors",
	})

	// totalDownloadErrors is the metric that reports the total number of download errors
	totalDownloadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_download_errors_total",
		Help: "The total number of download errors",
	})

	// totalUploadSize is the metric that reports the total uploads size as bytes
	totalUploadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_upload_size",
		Help: "The total upload size as bytes",
	})

	// totalDownloadSize is the metric that reports the total downloads size as bytes
	totalDownloadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_download_size",
		Help: "The total download size as bytes",
	})

	// totalLoginAttempts is the metric that reports the total number of login attempts
	totalLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_login_attempts_total",
		Help: "The total number of login attempts",
	})

	// totalLoginOK is the metric that reports the total number of successful logins
	totalLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_login_ok_total",
		Help: "The total number of successful logins",
	})

	// totalLoginFailed is the metric that reports the total number of failed logins
	totalLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_login_ko_total",
		Help: "The total number of failed logins",
	})

	// totalPasswordLoginAttempts is the metric that reports the total number of login attempts
	// using a password
	totalPasswordLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_password_login_attempts_total",
		Help: "The total number of login attempts using a password",
	})

	// totalPasswordLoginOK is the metric that reports the total number of successful logins
	// using a password
	totalPasswordLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_password_login_ok_total",
		Help: "The total number of successful logins using a password",
	})

	// totalPasswordLoginFailed is the metric that reports the total number of failed logins
	// using a password
	totalPasswordLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_password_login_ko_total",
		Help: "The total number of failed logins using a password",
	})

	// totalKeyLoginAttempts is the metric that reports the total number of login attempts
	// using a public key
	totalKeyLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_public_key_login_attempts_total",
		Help: "The total number of login attempts using a public key",
	})

	// totalKeyLoginOK is the metric that reports the total number of successful logins
	// using a public key
	totalKeyLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_public_key_login_ok_total",
		Help: "The total number of successful logins using a public key",
	})

	// totalKeyLoginFailed is the metric that reports the total number of failed logins
	// using a public key
	totalKeyLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_public_key_login_ko_total",
		Help: "The total number of failed logins using a public key",
	})

	totalHTTPRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_http_req_total",
		Help: "The total number of HTTP requests served",
	})

	totalHTTPOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_http_req_ok_total",
		Help: "The total number of HTTP requests served with 2xx status code",
	})

	totalHTTPClientErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_http_client_errors_total",
		Help: "The total number of HTTP requests served with 4xx status code",
	})

	totalHTTPServerErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_http_server_errors_total",
		Help: "The total number of HTTP requests served with 5xx status code",
	})
)

// TransferCompleted update metrics after an upload or a download
func TransferCompleted(bytesSent, bytesReceived int64, transferKind int, err error) {
	if transferKind == 0 {
		// upload
		if err == nil {
			totalUploads.Inc()
			totalUploadSize.Add(float64(bytesReceived))
		} else {
			totalUploadErrors.Inc()
		}
	} else {
		// download
		if err == nil {
			totalDownloads.Inc()
			totalDownloadSize.Add(float64(bytesSent))
		} else {
			totalDownloadErrors.Inc()
		}
	}
}

// UpdateDataProviderAvailability updates the metric for the data provider availability
func UpdateDataProviderAvailability(err error) {
	if err == nil {
		dataproviderAvailability.Set(1)
	} else {
		dataproviderAvailability.Set(0)
	}
}

// AddLoginAttempt increments the metrics for login attempts
func AddLoginAttempt(withKey bool) {
	totalLoginAttempts.Inc()
	if withKey {
		totalKeyLoginAttempts.Inc()
	} else {
		totalPasswordLoginAttempts.Inc()
	}
}

// AddLoginResult increments the metrics for login results
func AddLoginResult(withKey bool, err error) {
	if err == nil {
		totalLoginOK.Inc()
		if withKey {
			totalKeyLoginOK.Inc()
		} else {
			totalPasswordLoginOK.Inc()
		}
	} else {
		totalLoginFailed.Inc()
		if withKey {
			totalKeyLoginFailed.Inc()
		} else {
			totalPasswordLoginFailed.Inc()
		}
	}
}

// HTTPRequestServed increments the metrics for HTTP requests
func HTTPRequestServed(status int) {
	totalHTTPRequests.Inc()
	if status >= 200 && status < 300 {
		totalHTTPOK.Inc()
	} else if status >= 400 && status < 500 {
		totalHTTPClientErrors.Inc()
	} else if status >= 500 {
		totalHTTPServerErrors.Inc()
	}
}

// UpdateActiveConnectionsSize sets the metric for active connections
func UpdateActiveConnectionsSize(size int) {
	activeConnections.Set(float64(size))
}
