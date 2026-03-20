// Copyright (C) 2019 Nicola Murino
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

//go:build !nometrics

// Package metric provides Prometheus metrics support
package metric

import (
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/drakkan/sftpgo/v2/internal/version"
)

const (
	unknownUsername                 = "unknown"
	loginMethodPublicKey            = "publickey"
	loginMethodKeyboardInteractive  = "keyboard-interactive"
	loginMethodKeyAndPassword       = "publickey+password"
	loginMethodKeyAndKeyboardInt    = "publickey+keyboard-interactive"
	loginMethodTLSCertificate       = "TLSCertificate"
	loginMethodTLSCertificateAndPwd = "TLSCertificate+password"
	loginMethodIDP                  = "IDP"
)

func init() {
	version.AddFeature("+metrics")
}

var (
	// dataproviderAvailability is the metric that reports the availability for the configured data provider
	dataproviderAvailability = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sftpgo_dataprovider_availability",
		Help: "Availability for the configured data provider, 1 means OK, 0 KO",
	})

	// activeConnections is the metric that reports the total number of active connections
	activeConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sftpgo_active_connections",
		Help: "Total number of logged in users",
	}, []string{"username"})

	// totalUploads is the metric that reports the total number of successful uploads
	totalUploads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_uploads_total",
		Help: "The total number of successful uploads",
	}, []string{"username"})

	// totalDownloads is the metric that reports the total number of successful downloads
	totalDownloads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_downloads_total",
		Help: "The total number of successful downloads",
	}, []string{"username"})

	// totalUploadErrors is the metric that reports the total number of upload errors
	totalUploadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_upload_errors_total",
		Help: "The total number of upload errors",
	}, []string{"username"})

	// totalDownloadErrors is the metric that reports the total number of download errors
	totalDownloadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_download_errors_total",
		Help: "The total number of download errors",
	}, []string{"username"})

	// totalUploadSize is the metric that reports the total uploads size as bytes
	totalUploadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_upload_size",
		Help: "The total upload size as bytes, partial uploads are included",
	}, []string{"username"})

	// totalDownloadSize is the metric that reports the total downloads size as bytes
	totalDownloadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_download_size",
		Help: "The total download size as bytes, partial downloads are included",
	}, []string{"username"})

	// totalSSHCommands is the metric that reports the total number of executed SSH commands
	totalSSHCommands = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_ssh_commands_total",
		Help: "The total number of executed SSH commands",
	}, []string{"username"})

	// totalSSHCommandErrors is the metric that reports the total number of SSH command errors
	totalSSHCommandErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_ssh_command_errors_total",
		Help: "The total number of SSH command errors",
	}, []string{"username"})

	// totalLoginAttempts is the metric that reports the total number of login attempts
	totalLoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_login_attempts_total",
		Help: "The total number of login attempts",
	}, []string{"username"})

	// totalNoAuthTried is te metric that reports the total number of clients disconnected
	// for inactivity before trying to login
	totalNoAuthTried = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_no_auth_total",
		Help: "The total number of clients disconnected for inactivity before trying to login",
	})

	// totalLoginOK is the metric that reports the total number of successful logins
	totalLoginOK = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_login_ok_total",
		Help: "The total number of successful logins",
	}, []string{"username"})

	// totalLoginFailed is the metric that reports the total number of failed logins
	totalLoginFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_login_ko_total",
		Help: "The total number of failed logins",
	}, []string{"username"})

	// totalPasswordLoginAttempts is the metric that reports the total number of login attempts
	// using a password
	totalPasswordLoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_password_login_attempts_total",
		Help: "The total number of login attempts using a password",
	}, []string{"username"})

	// totalPasswordLoginOK is the metric that reports the total number of successful logins
	// using a password
	totalPasswordLoginOK = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_password_login_ok_total",
		Help: "The total number of successful logins using a password",
	}, []string{"username"})

	// totalPasswordLoginFailed is the metric that reports the total number of failed logins
	// using a password
	totalPasswordLoginFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_password_login_ko_total",
		Help: "The total number of failed logins using a password",
	}, []string{"username"})

	// totalKeyLoginAttempts is the metric that reports the total number of login attempts
	// using a public key
	totalKeyLoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_public_key_login_attempts_total",
		Help: "The total number of login attempts using a public key",
	}, []string{"username"})

	// totalKeyLoginOK is the metric that reports the total number of successful logins
	// using a public key
	totalKeyLoginOK = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_public_key_login_ok_total",
		Help: "The total number of successful logins using a public key",
	}, []string{"username"})

	// totalKeyLoginFailed is the metric that reports the total number of failed logins
	// using a public key
	totalKeyLoginFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_public_key_login_ko_total",
		Help: "The total number of failed logins using a public key",
	}, []string{"username"})

	// totalTLSCertLoginAttempts is the metric that reports the total number of login attempts
	// using a TLS certificate
	totalTLSCertLoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_login_attempts_total",
		Help: "The total number of login attempts using a TLS certificate",
	}, []string{"username"})

	// totalTLSCertLoginOK is the metric that reports the total number of successful logins
	// using a TLS certificate
	totalTLSCertLoginOK = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_login_ok_total",
		Help: "The total number of successful logins using a TLS certificate",
	}, []string{"username"})

	// totalTLSCertLoginFailed is the metric that reports the total number of failed logins
	// using a TLS certificate
	totalTLSCertLoginFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_login_ko_total",
		Help: "The total number of failed logins using a TLS certificate",
	}, []string{"username"})

	// totalTLSCertAndPwdLoginAttempts is the metric that reports the total number of login attempts
	// using a TLS certificate+password
	totalTLSCertAndPwdLoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_and_pwd_login_attempts_total",
		Help: "The total number of login attempts using a TLS certificate+password",
	}, []string{"username"})

	// totalTLSCertLoginOK is the metric that reports the total number of successful logins
	// using a TLS certificate+password
	totalTLSCertAndPwdLoginOK = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_and_pwd_login_ok_total",
		Help: "The total number of successful logins using a TLS certificate+password",
	}, []string{"username"})

	// totalTLSCertAndPwdLoginFailed is the metric that reports the total number of failed logins
	// using a TLS certificate+password
	totalTLSCertAndPwdLoginFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_and_pwd_login_ko_total",
		Help: "The total number of failed logins using a TLS certificate+password",
	}, []string{"username"})

	// totalInteractiveLoginAttempts is the metric that reports the total number of login attempts
	// using keyboard interactive authentication
	totalInteractiveLoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_keyboard_interactive_login_attempts_total",
		Help: "The total number of login attempts using keyboard interactive authentication",
	}, []string{"username"})

	// totalInteractiveLoginOK is the metric that reports the total number of successful logins
	// using keyboard interactive authentication
	totalInteractiveLoginOK = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_keyboard_interactive_login_ok_total",
		Help: "The total number of successful logins using keyboard interactive authentication",
	}, []string{"username"})

	// totalInteractiveLoginFailed is the metric that reports the total number of failed logins
	// using keyboard interactive authentication
	totalInteractiveLoginFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_keyboard_interactive_login_ko_total",
		Help: "The total number of failed logins using keyboard interactive authentication",
	}, []string{"username"})

	// totalKeyAndPasswordLoginAttempts is the metric that reports the total number of
	// login attempts using public key + password multi steps auth
	totalKeyAndPasswordLoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_key_and_password_login_attempts_total",
		Help: "The total number of login attempts using public key + password",
	}, []string{"username"})

	// totalKeyAndPasswordLoginOK is the metric that reports the total number of
	// successful logins using public key + password multi steps auth
	totalKeyAndPasswordLoginOK = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_key_and_password_login_ok_total",
		Help: "The total number of successful logins using public key + password",
	}, []string{"username"})

	// totalKeyAndPasswordLoginFailed is the metric that reports the total number of
	// failed logins using public key + password multi steps auth
	totalKeyAndPasswordLoginFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_key_and_password_login_ko_total",
		Help: "The total number of failed logins using  public key + password",
	}, []string{"username"})

	// totalKeyAndKeyIntLoginAttempts is the metric that reports the total number of
	// login attempts using public key + keyboard interactive multi steps auth
	totalKeyAndKeyIntLoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_key_and_keyboard_int_login_attempts_total",
		Help: "The total number of login attempts using public key + keyboard interactive",
	}, []string{"username"})

	// totalKeyAndKeyIntLoginOK is the metric that reports the total number of
	// successful logins using public key + keyboard interactive multi steps auth
	totalKeyAndKeyIntLoginOK = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_key_and_keyboard_int_login_ok_total",
		Help: "The total number of successful logins using public key + keyboard interactive",
	}, []string{"username"})

	// totalKeyAndKeyIntLoginFailed is the metric that reports the total number of
	// failed logins using public key + keyboard interactive multi steps auth
	totalKeyAndKeyIntLoginFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_key_and_keyboard_int_login_ko_total",
		Help: "The total number of failed logins using  public key + keyboard interactive",
	}, []string{"username"})

	// totalIDPLoginAttempts is the metric that reports the total number of
	// login attempts using identity providers
	totalIDPLoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_idp_login_attempts_total",
		Help: "The total number of login attempts using Identity Providers",
	}, []string{"username"})

	// totalIDPLoginOK is the metric that reports the total number of
	// successful logins using identity providers
	totalIDPLoginOK = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_idp_login_ok_total",
		Help: "The total number of successful logins using Identity Providers",
	}, []string{"username"})

	// totalIDPLoginFailed is the metric that reports the total number of
	// failed logins using identity providers
	totalIDPLoginFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_idp_login_ko_total",
		Help: "The total number of failed logins using  Identity Providers",
	}, []string{"username"})

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
	totalS3Uploads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_uploads_total",
		Help: "The total number of successful S3 uploads",
	}, []string{"username"})

	// totalS3Downloads is the metric that reports the total number of successful S3 downloads
	totalS3Downloads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_downloads_total",
		Help: "The total number of successful S3 downloads",
	}, []string{"username"})

	// totalS3UploadErrors is the metric that reports the total number of S3 upload errors
	totalS3UploadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_upload_errors_total",
		Help: "The total number of S3 upload errors",
	}, []string{"username"})

	// totalS3DownloadErrors is the metric that reports the total number of S3 download errors
	totalS3DownloadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_download_errors_total",
		Help: "The total number of S3 download errors",
	}, []string{"username"})

	// totalS3UploadSize is the metric that reports the total S3 uploads size as bytes
	totalS3UploadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_upload_size",
		Help: "The total S3 upload size as bytes, partial uploads are included",
	}, []string{"username"})

	// totalS3DownloadSize is the metric that reports the total S3 downloads size as bytes
	totalS3DownloadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_download_size",
		Help: "The total S3 download size as bytes, partial downloads are included",
	}, []string{"username"})

	// totalS3ListObjects is the metric that reports the total successful S3 list objects requests
	totalS3ListObjects = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_list_objects",
		Help: "The total number of successful S3 list objects requests",
	}, []string{"username"})

	// totalS3CopyObject is the metric that reports the total successful S3 copy object requests
	totalS3CopyObject = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_copy_object",
		Help: "The total number of successful S3 copy object requests",
	}, []string{"username"})

	// totalS3DeleteObject is the metric that reports the total successful S3 delete object requests
	totalS3DeleteObject = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_delete_object",
		Help: "The total number of successful S3 delete object requests",
	}, []string{"username"})

	// totalS3ListObjectsError is the metric that reports the total S3 list objects errors
	totalS3ListObjectsErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_list_objects_errors",
		Help: "The total number of S3 list objects errors",
	}, []string{"username"})

	// totalS3CopyObjectErrors is the metric that reports the total S3 copy object errors
	totalS3CopyObjectErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_copy_object_errors",
		Help: "The total number of S3 copy object errors",
	}, []string{"username"})

	// totalS3DeleteObjectErrors is the metric that reports the total S3 delete object errors
	totalS3DeleteObjectErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_delete_object_errors",
		Help: "The total number of S3 delete object errors",
	}, []string{"username"})

	// totalS3HeadObject is the metric that reports the total successful S3 head object requests
	totalS3HeadObject = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_head_object",
		Help: "The total number of successful S3 head object requests",
	}, []string{"username"})

	// totalS3HeadObjectErrors is the metric that reports the total S3 head object errors
	totalS3HeadObjectErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_s3_head_object_errors",
		Help: "The total number of S3 head object errors",
	}, []string{"username"})

	// totalGCSUploads is the metric that reports the total number of successful GCS uploads
	totalGCSUploads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_uploads_total",
		Help: "The total number of successful GCS uploads",
	}, []string{"username"})

	// totalGCSDownloads is the metric that reports the total number of successful GCS downloads
	totalGCSDownloads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_downloads_total",
		Help: "The total number of successful GCS downloads",
	}, []string{"username"})

	// totalGCSUploadErrors is the metric that reports the total number of GCS upload errors
	totalGCSUploadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_upload_errors_total",
		Help: "The total number of GCS upload errors",
	}, []string{"username"})

	// totalGCSDownloadErrors is the metric that reports the total number of GCS download errors
	totalGCSDownloadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_download_errors_total",
		Help: "The total number of GCS download errors",
	}, []string{"username"})

	// totalGCSUploadSize is the metric that reports the total GCS uploads size as bytes
	totalGCSUploadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_upload_size",
		Help: "The total GCS upload size as bytes, partial uploads are included",
	}, []string{"username"})

	// totalGCSDownloadSize is the metric that reports the total GCS downloads size as bytes
	totalGCSDownloadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_download_size",
		Help: "The total GCS download size as bytes, partial downloads are included",
	}, []string{"username"})

	// totalGCSListObjects is the metric that reports the total successful GCS list objects requests
	totalGCSListObjects = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_list_objects",
		Help: "The total number of successful GCS list objects requests",
	}, []string{"username"})

	// totalGCSCopyObject is the metric that reports the total successful GCS copy object requests
	totalGCSCopyObject = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_copy_object",
		Help: "The total number of successful GCS copy object requests",
	}, []string{"username"})

	// totalGCSDeleteObject is the metric that reports the total successful GCS delete object requests
	totalGCSDeleteObject = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_delete_object",
		Help: "The total number of successful GCS delete object requests",
	}, []string{"username"})

	// totalGCSListObjectsError is the metric that reports the total GCS list objects errors
	totalGCSListObjectsErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_list_objects_errors",
		Help: "The total number of GCS list objects errors",
	}, []string{"username"})

	// totalGCSCopyObjectErrors is the metric that reports the total GCS copy object errors
	totalGCSCopyObjectErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_copy_object_errors",
		Help: "The total number of GCS copy object errors",
	}, []string{"username"})

	// totalGCSDeleteObjectErrors is the metric that reports the total GCS delete object errors
	totalGCSDeleteObjectErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_delete_object_errors",
		Help: "The total number of GCS delete object errors",
	}, []string{"username"})

	// totalGCSHeadObject is the metric that reports the total successful GCS head object requests
	totalGCSHeadObject = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_head_object",
		Help: "The total number of successful GCS head object requests",
	}, []string{"username"})

	// totalGCSHeadObjectErrors is the metric that reports the total GCS head object errors
	totalGCSHeadObjectErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_gcs_head_object_errors",
		Help: "The total number of GCS head object errors",
	}, []string{"username"})

	// totalAZUploads is the metric that reports the total number of successful Azure uploads
	totalAZUploads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_uploads_total",
		Help: "The total number of successful Azure uploads",
	}, []string{"username"})

	// totalAZDownloads is the metric that reports the total number of successful Azure downloads
	totalAZDownloads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_downloads_total",
		Help: "The total number of successful Azure downloads",
	}, []string{"username"})

	// totalAZUploadErrors is the metric that reports the total number of Azure upload errors
	totalAZUploadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_upload_errors_total",
		Help: "The total number of Azure upload errors",
	}, []string{"username"})

	// totalAZDownloadErrors is the metric that reports the total number of Azure download errors
	totalAZDownloadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_download_errors_total",
		Help: "The total number of Azure download errors",
	}, []string{"username"})

	// totalAZUploadSize is the metric that reports the total Azure uploads size as bytes
	totalAZUploadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_upload_size",
		Help: "The total Azure upload size as bytes, partial uploads are included",
	}, []string{"username"})

	// totalAZDownloadSize is the metric that reports the total Azure downloads size as bytes
	totalAZDownloadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_download_size",
		Help: "The total Azure download size as bytes, partial downloads are included",
	}, []string{"username"})

	// totalAZListObjects is the metric that reports the total successful Azure list objects requests
	totalAZListObjects = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_list_objects",
		Help: "The total number of successful Azure list objects requests",
	}, []string{"username"})

	// totalAZCopyObject is the metric that reports the total successful Azure copy object requests
	totalAZCopyObject = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_copy_object",
		Help: "The total number of successful Azure copy object requests",
	}, []string{"username"})

	// totalAZDeleteObject is the metric that reports the total successful Azure delete object requests
	totalAZDeleteObject = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_delete_object",
		Help: "The total number of successful Azure delete object requests",
	}, []string{"username"})

	// totalAZListObjectsError is the metric that reports the total Azure list objects errors
	totalAZListObjectsErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_list_objects_errors",
		Help: "The total number of Azure list objects errors",
	}, []string{"username"})

	// totalAZCopyObjectErrors is the metric that reports the total Azure copy object errors
	totalAZCopyObjectErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_copy_object_errors",
		Help: "The total number of Azure copy object errors",
	}, []string{"username"})

	// totalAZDeleteObjectErrors is the metric that reports the total Azure delete object errors
	totalAZDeleteObjectErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_delete_object_errors",
		Help: "The total number of Azure delete object errors",
	}, []string{"username"})

	// totalAZHeadObject is the metric that reports the total successful Azure head object requests
	totalAZHeadObject = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_head_object",
		Help: "The total number of successful Azure head object requests",
	}, []string{"username"})

	// totalAZHeadObjectErrors is the metric that reports the total Azure head object errors
	totalAZHeadObjectErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_az_head_object_errors",
		Help: "The total number of Azure head object errors",
	}, []string{"username"})

	// totalSFTPFsUploads is the metric that reports the total number of successful SFTPFs uploads
	totalSFTPFsUploads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_sftpfs_uploads_total",
		Help: "The total number of successful SFTPFs uploads",
	}, []string{"username"})

	// totalSFTPFsDownloads is the metric that reports the total number of successful SFTPFs downloads
	totalSFTPFsDownloads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_sftpfs_downloads_total",
		Help: "The total number of successful SFTPFs downloads",
	}, []string{"username"})

	// totalSFTPFsUploadErrors is the metric that reports the total number of SFTPFs upload errors
	totalSFTPFsUploadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_sftpfs_upload_errors_total",
		Help: "The total number of SFTPFs upload errors",
	}, []string{"username"})

	// totalSFTPFsDownloadErrors is the metric that reports the total number of SFTPFs download errors
	totalSFTPFsDownloadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_sftpfs_download_errors_total",
		Help: "The total number of SFTPFs download errors",
	}, []string{"username"})

	// totalSFTPFsUploadSize is the metric that reports the total SFTPFs uploads size as bytes
	totalSFTPFsUploadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_sftpfs_upload_size",
		Help: "The total SFTPFs upload size as bytes, partial uploads are included",
	}, []string{"username"})

	// totalSFTPFsDownloadSize is the metric that reports the total SFTPFs downloads size as bytes
	totalSFTPFsDownloadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_sftpfs_download_size",
		Help: "The total SFTPFs download size as bytes, partial downloads are included",
	}, []string{"username"})

	// totalHTTPFsUploads is the metric that reports the total number of successful HTTPFs uploads
	totalHTTPFsUploads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_httpfs_uploads_total",
		Help: "The total number of successful HTTPFs uploads",
	}, []string{"username"})

	// totalHTTPFsDownloads is the metric that reports the total number of successful HTTPFs downloads
	totalHTTPFsDownloads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_httpfs_downloads_total",
		Help: "The total number of successful HTTPFs downloads",
	}, []string{"username"})

	// totalHTTPFsUploadErrors is the metric that reports the total number of HTTPFs upload errors
	totalHTTPFsUploadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_httpfs_upload_errors_total",
		Help: "The total number of HTTPFs upload errors",
	}, []string{"username"})

	// totalHTTPFsDownloadErrors is the metric that reports the total number of HTTPFs download errors
	totalHTTPFsDownloadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_httpfs_download_errors_total",
		Help: "The total number of HTTPFs download errors",
	}, []string{"username"})

	// totalHTTPFsUploadSize is the metric that reports the total HTTPFs uploads size as bytes
	totalHTTPFsUploadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_httpfs_upload_size",
		Help: "The total HTTPFs upload size as bytes, partial uploads are included",
	}, []string{"username"})

	// totalHTTPFsDownloadSize is the metric that reports the total HTTPFs downloads size as bytes
	totalHTTPFsDownloadSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sftpgo_httpfs_download_size",
		Help: "The total HTTPFs download size as bytes, partial downloads are included",
	}, []string{"username"})
)

// AddMetricsEndpoint publishes metrics to the specified endpoint
func AddMetricsEndpoint(metricsPath string, handler chi.Router) {
	handler.Handle(metricsPath, promhttp.Handler())
}

// TransferCompleted updates metrics after an upload or a download
func TransferCompleted(bytesSent, bytesReceived int64, transferKind int, err error, isSFTPFs bool, username string) {
	if username == "" {
		username = unknownUsername
	}
	if transferKind == 0 {
		// upload
		if err == nil {
			totalUploads.WithLabelValues(username).Inc()
		} else {
			totalUploadErrors.WithLabelValues(username).Inc()
		}
	} else {
		// download
		if err == nil {
			totalDownloads.WithLabelValues(username).Inc()
		} else {
			totalDownloadErrors.WithLabelValues(username).Inc()
		}
	}
	if bytesReceived > 0 {
		totalUploadSize.WithLabelValues(username).Add(float64(bytesReceived))
	}
	if bytesSent > 0 {
		totalDownloadSize.WithLabelValues(username).Add(float64(bytesSent))
	}
	if isSFTPFs {
		sftpFsTransferCompleted(bytesSent, bytesReceived, transferKind, err, username)
	}
}

// S3TransferCompleted updates metrics after an S3 upload or a download
func S3TransferCompleted(bytes int64, transferKind int, err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if transferKind == 0 {
		// upload
		if err == nil {
			totalS3Uploads.WithLabelValues(username).Inc()
		} else {
			totalS3UploadErrors.WithLabelValues(username).Inc()
		}
		totalS3UploadSize.WithLabelValues(username).Add(float64(bytes))
	} else {
		// download
		if err == nil {
			totalS3Downloads.WithLabelValues(username).Inc()
		} else {
			totalS3DownloadErrors.WithLabelValues(username).Inc()
		}
		totalS3DownloadSize.WithLabelValues(username).Add(float64(bytes))
	}
}

// S3ListObjectsCompleted updates metrics after an S3 list objects request terminates
func S3ListObjectsCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalS3ListObjects.WithLabelValues(username).Inc()
	} else {
		totalS3ListObjectsErrors.WithLabelValues(username).Inc()
	}
}

// S3CopyObjectCompleted updates metrics after an S3 copy object request terminates
func S3CopyObjectCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalS3CopyObject.WithLabelValues(username).Inc()
	} else {
		totalS3CopyObjectErrors.WithLabelValues(username).Inc()
	}
}

// S3DeleteObjectCompleted updates metrics after an S3 delete object request terminates
func S3DeleteObjectCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalS3DeleteObject.WithLabelValues(username).Inc()
	} else {
		totalS3DeleteObjectErrors.WithLabelValues(username).Inc()
	}
}

// S3HeadObjectCompleted updates metrics after a S3 head object request terminates
func S3HeadObjectCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalS3HeadObject.WithLabelValues(username).Inc()
	} else {
		totalS3HeadObjectErrors.WithLabelValues(username).Inc()
	}
}

// GCSTransferCompleted updates metrics after a GCS upload or a download
func GCSTransferCompleted(bytes int64, transferKind int, err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if transferKind == 0 {
		// upload
		if err == nil {
			totalGCSUploads.WithLabelValues(username).Inc()
		} else {
			totalGCSUploadErrors.WithLabelValues(username).Inc()
		}
		totalGCSUploadSize.WithLabelValues(username).Add(float64(bytes))
	} else {
		// download
		if err == nil {
			totalGCSDownloads.WithLabelValues(username).Inc()
		} else {
			totalGCSDownloadErrors.WithLabelValues(username).Inc()
		}
		totalGCSDownloadSize.WithLabelValues(username).Add(float64(bytes))
	}
}

// GCSListObjectsCompleted updates metrics after a GCS list objects request terminates
func GCSListObjectsCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalGCSListObjects.WithLabelValues(username).Inc()
	} else {
		totalGCSListObjectsErrors.WithLabelValues(username).Inc()
	}
}

// GCSCopyObjectCompleted updates metrics after a GCS copy object request terminates
func GCSCopyObjectCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalGCSCopyObject.WithLabelValues(username).Inc()
	} else {
		totalGCSCopyObjectErrors.WithLabelValues(username).Inc()
	}
}

// GCSDeleteObjectCompleted updates metrics after a GCS delete object request terminates
func GCSDeleteObjectCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalGCSDeleteObject.WithLabelValues(username).Inc()
	} else {
		totalGCSDeleteObjectErrors.WithLabelValues(username).Inc()
	}
}

// GCSHeadObjectCompleted updates metrics after a GCS head object request terminates
func GCSHeadObjectCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalGCSHeadObject.WithLabelValues(username).Inc()
	} else {
		totalGCSHeadObjectErrors.WithLabelValues(username).Inc()
	}
}

// AZTransferCompleted updates metrics after a Azure upload or a download
func AZTransferCompleted(bytes int64, transferKind int, err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if transferKind == 0 {
		// upload
		if err == nil {
			totalAZUploads.WithLabelValues(username).Inc()
		} else {
			totalAZUploadErrors.WithLabelValues(username).Inc()
		}
		totalAZUploadSize.WithLabelValues(username).Add(float64(bytes))
	} else {
		// download
		if err == nil {
			totalAZDownloads.WithLabelValues(username).Inc()
		} else {
			totalAZDownloadErrors.WithLabelValues(username).Inc()
		}
		totalAZDownloadSize.WithLabelValues(username).Add(float64(bytes))
	}
}

// AZListObjectsCompleted updates metrics after a Azure list objects request terminates
func AZListObjectsCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalAZListObjects.WithLabelValues(username).Inc()
	} else {
		totalAZListObjectsErrors.WithLabelValues(username).Inc()
	}
}

// AZCopyObjectCompleted updates metrics after a Azure copy object request terminates
func AZCopyObjectCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalAZCopyObject.WithLabelValues(username).Inc()
	} else {
		totalAZCopyObjectErrors.WithLabelValues(username).Inc()
	}
}

// AZDeleteObjectCompleted updates metrics after a Azure delete object request terminates
func AZDeleteObjectCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalAZDeleteObject.WithLabelValues(username).Inc()
	} else {
		totalAZDeleteObjectErrors.WithLabelValues(username).Inc()
	}
}

// AZHeadObjectCompleted updates metrics after a Azure head object request terminates
func AZHeadObjectCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalAZHeadObject.WithLabelValues(username).Inc()
	} else {
		totalAZHeadObjectErrors.WithLabelValues(username).Inc()
	}
}

// sftpFsTransferCompleted updates metrics after an SFTPFs upload or a download
func sftpFsTransferCompleted(bytesSent, bytesReceived int64, transferKind int, err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if transferKind == 0 {
		// upload
		if err == nil {
			totalSFTPFsUploads.WithLabelValues(username).Inc()
		} else {
			totalSFTPFsUploadErrors.WithLabelValues(username).Inc()
		}
	} else {
		// download
		if err == nil {
			totalSFTPFsDownloads.WithLabelValues(username).Inc()
		} else {
			totalSFTPFsDownloadErrors.WithLabelValues(username).Inc()
		}
	}
	if bytesReceived > 0 {
		totalSFTPFsUploadSize.WithLabelValues(username).Add(float64(bytesReceived))
	}
	if bytesSent > 0 {
		totalSFTPFsDownloadSize.WithLabelValues(username).Add(float64(bytesSent))
	}
}

// HTTPFsTransferCompleted updates metrics after an HTTPFs upload or a download
func HTTPFsTransferCompleted(bytes int64, transferKind int, err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if transferKind == 0 {
		// upload
		if err == nil {
			totalHTTPFsUploads.WithLabelValues(username).Inc()
		} else {
			totalHTTPFsUploadErrors.WithLabelValues(username).Inc()
		}
		totalHTTPFsUploadSize.WithLabelValues(username).Add(float64(bytes))
	} else {
		// download
		if err == nil {
			totalHTTPFsDownloads.WithLabelValues(username).Inc()
		} else {
			totalHTTPFsDownloadErrors.WithLabelValues(username).Inc()
		}
		totalHTTPFsDownloadSize.WithLabelValues(username).Add(float64(bytes))
	}
}

// SSHCommandCompleted update metrics after an SSH command terminates
func SSHCommandCompleted(err error, username string) {
	if username == "" {
		username = unknownUsername
	}
	if err == nil {
		totalSSHCommands.WithLabelValues(username).Inc()
	} else {
		totalSSHCommandErrors.WithLabelValues(username).Inc()
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
func AddLoginAttempt(authMethod string, username string) {
	if username == "" {
		username = unknownUsername
	}
	totalLoginAttempts.WithLabelValues(username).Inc()
	switch authMethod {
	case loginMethodPublicKey:
		totalKeyLoginAttempts.WithLabelValues(username).Inc()
	case loginMethodKeyboardInteractive:
		totalInteractiveLoginAttempts.WithLabelValues(username).Inc()
	case loginMethodKeyAndPassword:
		totalKeyAndPasswordLoginAttempts.WithLabelValues(username).Inc()
	case loginMethodKeyAndKeyboardInt:
		totalKeyAndKeyIntLoginAttempts.WithLabelValues(username).Inc()
	case loginMethodTLSCertificate:
		totalTLSCertLoginAttempts.WithLabelValues(username).Inc()
	case loginMethodTLSCertificateAndPwd:
		totalTLSCertAndPwdLoginAttempts.WithLabelValues(username).Inc()
	case loginMethodIDP:
		totalIDPLoginAttempts.WithLabelValues(username).Inc()
	default:
		totalPasswordLoginAttempts.WithLabelValues(username).Inc()
	}
}

func incLoginOK(authMethod string, username string) {
	if username == "" {
		username = unknownUsername
	}
	totalLoginOK.WithLabelValues(username).Inc()
	switch authMethod {
	case loginMethodPublicKey:
		totalKeyLoginOK.WithLabelValues(username).Inc()
	case loginMethodKeyboardInteractive:
		totalInteractiveLoginOK.WithLabelValues(username).Inc()
	case loginMethodKeyAndPassword:
		totalKeyAndPasswordLoginOK.WithLabelValues(username).Inc()
	case loginMethodKeyAndKeyboardInt:
		totalKeyAndKeyIntLoginOK.WithLabelValues(username).Inc()
	case loginMethodTLSCertificate:
		totalTLSCertLoginOK.WithLabelValues(username).Inc()
	case loginMethodTLSCertificateAndPwd:
		totalTLSCertAndPwdLoginOK.WithLabelValues(username).Inc()
	case loginMethodIDP:
		totalIDPLoginOK.WithLabelValues(username).Inc()
	default:
		totalPasswordLoginOK.WithLabelValues(username).Inc()
	}
}

func incLoginFailed(authMethod string, username string) {
	if username == "" {
		username = unknownUsername
	}
	totalLoginFailed.WithLabelValues(username).Inc()
	switch authMethod {
	case loginMethodPublicKey:
		totalKeyLoginFailed.WithLabelValues(username).Inc()
	case loginMethodKeyboardInteractive:
		totalInteractiveLoginFailed.WithLabelValues(username).Inc()
	case loginMethodKeyAndPassword:
		totalKeyAndPasswordLoginFailed.WithLabelValues(username).Inc()
	case loginMethodKeyAndKeyboardInt:
		totalKeyAndKeyIntLoginFailed.WithLabelValues(username).Inc()
	case loginMethodTLSCertificate:
		totalTLSCertLoginFailed.WithLabelValues(username).Inc()
	case loginMethodTLSCertificateAndPwd:
		totalTLSCertAndPwdLoginFailed.WithLabelValues(username).Inc()
	case loginMethodIDP:
		totalIDPLoginFailed.WithLabelValues(username).Inc()
	default:
		totalPasswordLoginFailed.WithLabelValues(username).Inc()
	}
}

// AddLoginResult increments the metrics for login results
func AddLoginResult(authMethod string, err error, username string) {
	if err == nil {
		incLoginOK(authMethod, username)
	} else {
		incLoginFailed(authMethod, username)
	}
}

// AddNoAuthTried increments the metric for clients disconnected
// for inactivity before trying to login
func AddNoAuthTried() {
	totalNoAuthTried.Inc()
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
func UpdateActiveConnectionsSize(size int, username string) {
	if username == "" {
		username = unknownUsername
	}
	activeConnections.WithLabelValues(username).Set(float64(size))
}
