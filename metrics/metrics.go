// Package metrics provides Prometheus metrics support
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

	// totalUploads is the metric that reports the total number of successful SFTP/SCP uploads
	totalUploads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_uploads_total",
		Help: "The total number of successful SFTP/SCP uploads",
	})

	// totalDownloads is the metric that reports the total number of successful SFTP/SCP downloads
	totalDownloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_downloads_total",
		Help: "The total number of successful SFTP/SCP downloads",
	})

	// totalUploadErrors is the metric that reports the total number of SFTP/SCP upload errors
	totalUploadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_upload_errors_total",
		Help: "The total number of SFTP/SCP upload errors",
	})

	// totalDownloadErrors is the metric that reports the total number of SFTP/SCP download errors
	totalDownloadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_download_errors_total",
		Help: "The total number of SFTP/SCP download errors",
	})

	// totalUploadSize is the metric that reports the total SFTP/SCP uploads size as bytes
	totalUploadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_upload_size",
		Help: "The total SFTP/SCP upload size as bytes, partial uploads are included",
	})

	// totalDownloadSize is the metric that reports the total SFTP/SCP downloads size as bytes
	totalDownloadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_download_size",
		Help: "The total SFTP/SCP download size as bytes, partial downloads are included",
	})

	// totalSSHCommands is the metric that reports the total number of executed SSH commands
	totalSSHCommands = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_ssh_commands_total",
		Help: "The total number of executed SSH commands",
	})

	// totalSSHCommandErrors is the metric that reports the total number of SSH command errors
	totalSSHCommandErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_ssh_command_errors_total",
		Help: "The total number of SSH command errors",
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

	// totalInteractiveLoginAttempts is the metric that reports the total number of login attempts
	// using keyboard interactive authentication
	totalInteractiveLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_keyboard_interactive_login_attempts_total",
		Help: "The total number of login attempts using keyboard interactive authentication",
	})

	// totalInteractiveLoginOK is the metric that reports the total number of successful logins
	// using keyboard interactive authentication
	totalInteractiveLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_keyboard_interactive_login_ok_total",
		Help: "The total number of successful logins using keyboard interactive authentication",
	})

	// totalInteractiveLoginFailed is the metric that reports the total number of failed logins
	// using keyboard interactive authentication
	totalInteractiveLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_keyboard_interactive_login_ko_total",
		Help: "The total number of failed logins using keyboard interactive authentication",
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

	// totalS3Uploads is the metric that reports the total number of successful S3 uploads
	totalS3Uploads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_uploads_total",
		Help: "The total number of successful S3 uploads",
	})

	// totalS3Downloads is the metric that reports the total number of successful S3 downloads
	totalS3Downloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_downloads_total",
		Help: "The total number of successful S3 downloads",
	})

	// totalS3UploadErrors is the metric that reports the total number of S3 upload errors
	totalS3UploadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_upload_errors_total",
		Help: "The total number of S3 upload errors",
	})

	// totalS3DownloadErrors is the metric that reports the total number of S3 download errors
	totalS3DownloadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_download_errors_total",
		Help: "The total number of S3 download errors",
	})

	// totalS3UploadSize is the metric that reports the total S3 uploads size as bytes
	totalS3UploadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_upload_size",
		Help: "The total S3 upload size as bytes, partial uploads are included",
	})

	// totalS3DownloadSize is the metric that reports the total S3 downloads size as bytes
	totalS3DownloadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_download_size",
		Help: "The total S3 download size as bytes, partial downloads are included",
	})

	// totalS3ListObjects is the metric that reports the total successful S3 list objects requests
	totalS3ListObjects = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_list_objects",
		Help: "The total number of successful S3 list objects requests",
	})

	// totalS3CopyObject is the metric that reports the total successful S3 copy object requests
	totalS3CopyObject = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_copy_object",
		Help: "The total number of successful S3 copy object requests",
	})

	// totalS3DeleteObject is the metric that reports the total successful S3 delete object requests
	totalS3DeleteObject = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_delete_object",
		Help: "The total number of successful S3 delete object requests",
	})

	// totalS3ListObjectsError is the metric that reports the total S3 list objects errors
	totalS3ListObjectsErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_list_objects_errors",
		Help: "The total number of S3 list objects errors",
	})

	// totalS3CopyObjectErrors is the metric that reports the total S3 copy object errors
	totalS3CopyObjectErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_copy_object_errors",
		Help: "The total number of S3 copy object errors",
	})

	// totalS3DeleteObjectErrors is the metric that reports the total S3 delete object errors
	totalS3DeleteObjectErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_delete_object_errors",
		Help: "The total number of S3 delete object errors",
	})

	// totalS3HeadBucket is the metric that reports the total successful S3 head bucket requests
	totalS3HeadBucket = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_head_bucket",
		Help: "The total number of successful S3 head bucket requests",
	})

	// totalS3CreateBucket is the metric that reports the total successful S3 create bucket requests
	totalS3CreateBucket = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_create_bucket",
		Help: "The total number of successful S3 create bucket requests",
	})

	// totalS3HeadBucketErrors is the metric that reports the total S3 head bucket errors
	totalS3HeadBucketErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_head_bucket_errors",
		Help: "The total number of S3 head bucket errors",
	})

	// totalS3CreateBucketErrors is the metric that reports the total S3 create bucket errors
	totalS3CreateBucketErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_create_bucket_errors",
		Help: "The total number of S3 create bucket errors",
	})
)

// TransferCompleted updates metrics after an upload or a download
func TransferCompleted(bytesSent, bytesReceived int64, transferKind int, err error) {
	if transferKind == 0 {
		// upload
		if err == nil {
			totalUploads.Inc()
		} else {
			totalUploadErrors.Inc()
		}
		totalUploadSize.Add(float64(bytesReceived))
	} else {
		// download
		if err == nil {
			totalDownloads.Inc()
		} else {
			totalDownloadErrors.Inc()
		}
		totalDownloadSize.Add(float64(bytesSent))
	}
}

// S3TransferCompleted updates metrics after an S3 upload or a download
func S3TransferCompleted(bytes int64, transferKind int, err error) {
	if transferKind == 0 {
		// upload
		if err == nil {
			totalS3Uploads.Inc()
		} else {
			totalS3UploadErrors.Inc()
		}
		totalS3UploadSize.Add(float64(bytes))
	} else {
		// download
		if err == nil {
			totalS3Downloads.Inc()
		} else {
			totalS3DownloadErrors.Inc()
		}
		totalS3DownloadSize.Add(float64(bytes))
	}
}

// S3ListObjectsCompleted updates metrics after an S3 list objects request terminates
func S3ListObjectsCompleted(err error) {
	if err == nil {
		totalS3ListObjects.Inc()
	} else {
		totalS3ListObjectsErrors.Inc()
	}
}

// S3CopyObjectCompleted updates metrics after an S3 copy object request terminates
func S3CopyObjectCompleted(err error) {
	if err == nil {
		totalS3CopyObject.Inc()
	} else {
		totalS3CopyObjectErrors.Inc()
	}
}

// S3DeleteObjectCompleted updates metrics after an S3 delete object request terminates
func S3DeleteObjectCompleted(err error) {
	if err == nil {
		totalS3DeleteObject.Inc()
	} else {
		totalS3DeleteObjectErrors.Inc()
	}
}

// S3HeadBucketCompleted updates metrics after an S3 head bucket request terminates
func S3HeadBucketCompleted(err error) {
	if err == nil {
		totalS3HeadBucket.Inc()
	} else {
		totalS3HeadBucketErrors.Inc()
	}
}

// S3CreateBucketCompleted updates metrics after an S3 create bucket request terminates
func S3CreateBucketCompleted(err error) {
	if err == nil {
		totalS3CreateBucket.Inc()
	} else {
		totalS3CreateBucketErrors.Inc()
	}
}

// SSHCommandCompleted update metrics after an SSH command terminates
func SSHCommandCompleted(err error) {
	if err == nil {
		totalSSHCommands.Inc()
	} else {
		totalSSHCommandErrors.Inc()
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
func AddLoginAttempt(authMethod string) {
	totalLoginAttempts.Inc()
	switch authMethod {
	case "public_key":
		totalKeyLoginAttempts.Inc()
	case "keyboard-interactive":
		totalInteractiveLoginAttempts.Inc()
	default:
		totalPasswordLoginAttempts.Inc()
	}
}

// AddLoginResult increments the metrics for login results
func AddLoginResult(authMethod string, err error) {
	if err == nil {
		totalLoginOK.Inc()
		switch authMethod {
		case "public_key":
			totalKeyLoginOK.Inc()
		case "keyboard-interactive":
			totalInteractiveLoginOK.Inc()
		default:
			totalPasswordLoginOK.Inc()
		}
	} else {
		totalLoginFailed.Inc()
		switch authMethod {
		case "public_key":
			totalKeyLoginFailed.Inc()
		case "keyboard-interactive":
			totalInteractiveLoginFailed.Inc()
		default:
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
