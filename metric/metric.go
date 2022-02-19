//go:build !nometrics
// +build !nometrics

// Package metric provides Prometheus metrics support
package metric

import (
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/drakkan/sftpgo/v2/version"
)

const (
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
	activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sftpgo_active_connections",
		Help: "Total number of logged in users",
	})

	// totalUploads is the metric that reports the total number of successful uploads
	totalUploads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_uploads_total",
		Help: "The total number of successful uploads",
	})

	// totalDownloads is the metric that reports the total number of successful downloads
	totalDownloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_downloads_total",
		Help: "The total number of successful downloads",
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
		Help: "The total upload size as bytes, partial uploads are included",
	})

	// totalDownloadSize is the metric that reports the total downloads size as bytes
	totalDownloadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_download_size",
		Help: "The total download size as bytes, partial downloads are included",
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

	// totalNoAuthTryed is te metric that reports the total number of clients disconnected
	// for inactivity before trying to login
	totalNoAuthTryed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_no_auth_total",
		Help: "The total number of clients disconnected for inactivity before trying to login",
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

	// totalTLSCertLoginAttempts is the metric that reports the total number of login attempts
	// using a TLS certificate
	totalTLSCertLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_login_attempts_total",
		Help: "The total number of login attempts using a TLS certificate",
	})

	// totalTLSCertLoginOK is the metric that reports the total number of successful logins
	// using a TLS certificate
	totalTLSCertLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_login_ok_total",
		Help: "The total number of successful logins using a TLS certificate",
	})

	// totalTLSCertLoginFailed is the metric that reports the total number of failed logins
	// using a TLS certificate
	totalTLSCertLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_login_ko_total",
		Help: "The total number of failed logins using a TLS certificate",
	})

	// totalTLSCertAndPwdLoginAttempts is the metric that reports the total number of login attempts
	// using a TLS certificate+password
	totalTLSCertAndPwdLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_and_pwd_login_attempts_total",
		Help: "The total number of login attempts using a TLS certificate+password",
	})

	// totalTLSCertLoginOK is the metric that reports the total number of successful logins
	// using a TLS certificate+password
	totalTLSCertAndPwdLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_and_pwd_login_ok_total",
		Help: "The total number of successful logins using a TLS certificate+password",
	})

	// totalTLSCertAndPwdLoginFailed is the metric that reports the total number of failed logins
	// using a TLS certificate+password
	totalTLSCertAndPwdLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_tls_cert_and_pwd_login_ko_total",
		Help: "The total number of failed logins using a TLS certificate+password",
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

	// totalKeyAndPasswordLoginAttempts is the metric that reports the total number of
	// login attempts using public key + password multi steps auth
	totalKeyAndPasswordLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_password_login_attempts_total",
		Help: "The total number of login attempts using public key + password",
	})

	// totalKeyAndPasswordLoginOK is the metric that reports the total number of
	// successful logins using public key + password multi steps auth
	totalKeyAndPasswordLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_password_login_ok_total",
		Help: "The total number of successful logins using public key + password",
	})

	// totalKeyAndPasswordLoginFailed is the metric that reports the total number of
	// failed logins using public key + password multi steps auth
	totalKeyAndPasswordLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_password_login_ko_total",
		Help: "The total number of failed logins using  public key + password",
	})

	// totalKeyAndKeyIntLoginAttempts is the metric that reports the total number of
	// login attempts using public key + keyboard interactive multi steps auth
	totalKeyAndKeyIntLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_keyboard_int_login_attempts_total",
		Help: "The total number of login attempts using public key + keyboard interactive",
	})

	// totalKeyAndKeyIntLoginOK is the metric that reports the total number of
	// successful logins using public key + keyboard interactive multi steps auth
	totalKeyAndKeyIntLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_keyboard_int_login_ok_total",
		Help: "The total number of successful logins using public key + keyboard interactive",
	})

	// totalKeyAndKeyIntLoginFailed is the metric that reports the total number of
	// failed logins using public key + keyboard interactive multi steps auth
	totalKeyAndKeyIntLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_keyboard_int_login_ko_total",
		Help: "The total number of failed logins using  public key + keyboard interactive",
	})

	// totalIDPLoginAttempts is the metric that reports the total number of
	// login attempts using identity providers
	totalIDPLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_idp_login_attempts_total",
		Help: "The total number of login attempts using Identity Providers",
	})

	// totalIDPLoginOK is the metric that reports the total number of
	// successful logins using identity providers
	totalIDPLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_idp_login_ok_total",
		Help: "The total number of successful logins using Identity Providers",
	})

	// totalIDPLoginFailed is the metric that reports the total number of
	// failed logins using identity providers
	totalIDPLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_idp_login_ko_total",
		Help: "The total number of failed logins using  Identity Providers",
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

	// totalS3HeadObject is the metric that reports the total successful S3 head object requests
	totalS3HeadObject = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_head_object",
		Help: "The total number of successful S3 head object requests",
	})

	// totalS3HeadObjectErrors is the metric that reports the total S3 head object errors
	totalS3HeadObjectErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_head_object_errors",
		Help: "The total number of S3 head object errors",
	})

	// totalS3HeadBucket is the metric that reports the total successful S3 head bucket requests
	totalS3HeadBucket = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_head_bucket",
		Help: "The total number of successful S3 head bucket requests",
	})

	// totalS3HeadBucketErrors is the metric that reports the total S3 head bucket errors
	totalS3HeadBucketErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_s3_head_bucket_errors",
		Help: "The total number of S3 head bucket errors",
	})

	// totalGCSUploads is the metric that reports the total number of successful GCS uploads
	totalGCSUploads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_uploads_total",
		Help: "The total number of successful GCS uploads",
	})

	// totalGCSDownloads is the metric that reports the total number of successful GCS downloads
	totalGCSDownloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_downloads_total",
		Help: "The total number of successful GCS downloads",
	})

	// totalGCSUploadErrors is the metric that reports the total number of GCS upload errors
	totalGCSUploadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_upload_errors_total",
		Help: "The total number of GCS upload errors",
	})

	// totalGCSDownloadErrors is the metric that reports the total number of GCS download errors
	totalGCSDownloadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_download_errors_total",
		Help: "The total number of GCS download errors",
	})

	// totalGCSUploadSize is the metric that reports the total GCS uploads size as bytes
	totalGCSUploadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_upload_size",
		Help: "The total GCS upload size as bytes, partial uploads are included",
	})

	// totalGCSDownloadSize is the metric that reports the total GCS downloads size as bytes
	totalGCSDownloadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_download_size",
		Help: "The total GCS download size as bytes, partial downloads are included",
	})

	// totalGCSListObjects is the metric that reports the total successful GCS list objects requests
	totalGCSListObjects = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_list_objects",
		Help: "The total number of successful GCS list objects requests",
	})

	// totalGCSCopyObject is the metric that reports the total successful GCS copy object requests
	totalGCSCopyObject = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_copy_object",
		Help: "The total number of successful GCS copy object requests",
	})

	// totalGCSDeleteObject is the metric that reports the total successful GCS delete object requests
	totalGCSDeleteObject = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_delete_object",
		Help: "The total number of successful GCS delete object requests",
	})

	// totalGCSListObjectsError is the metric that reports the total GCS list objects errors
	totalGCSListObjectsErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_list_objects_errors",
		Help: "The total number of GCS list objects errors",
	})

	// totalGCSCopyObjectErrors is the metric that reports the total GCS copy object errors
	totalGCSCopyObjectErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_copy_object_errors",
		Help: "The total number of GCS copy object errors",
	})

	// totalGCSDeleteObjectErrors is the metric that reports the total GCS delete object errors
	totalGCSDeleteObjectErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_delete_object_errors",
		Help: "The total number of GCS delete object errors",
	})

	// totalGCSHeadObject is the metric that reports the total successful GCS head object requests
	totalGCSHeadObject = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_head_object",
		Help: "The total number of successful GCS head object requests",
	})

	// totalGCSHeadObjectErrors is the metric that reports the total GCS head object errors
	totalGCSHeadObjectErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_head_object_errors",
		Help: "The total number of GCS head object errors",
	})

	// totalGCSHeadBucket is the metric that reports the total successful GCS head bucket requests
	totalGCSHeadBucket = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_head_bucket",
		Help: "The total number of successful GCS head bucket requests",
	})

	// totalGCSHeadBucketErrors is the metric that reports the total GCS head bucket errors
	totalGCSHeadBucketErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_gcs_head_bucket_errors",
		Help: "The total number of GCS head bucket errors",
	})

	// totalAZUploads is the metric that reports the total number of successful Azure uploads
	totalAZUploads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_uploads_total",
		Help: "The total number of successful Azure uploads",
	})

	// totalAZDownloads is the metric that reports the total number of successful Azure downloads
	totalAZDownloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_downloads_total",
		Help: "The total number of successful Azure downloads",
	})

	// totalAZUploadErrors is the metric that reports the total number of Azure upload errors
	totalAZUploadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_upload_errors_total",
		Help: "The total number of Azure upload errors",
	})

	// totalAZDownloadErrors is the metric that reports the total number of Azure download errors
	totalAZDownloadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_download_errors_total",
		Help: "The total number of Azure download errors",
	})

	// totalAZUploadSize is the metric that reports the total Azure uploads size as bytes
	totalAZUploadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_upload_size",
		Help: "The total Azure upload size as bytes, partial uploads are included",
	})

	// totalAZDownloadSize is the metric that reports the total Azure downloads size as bytes
	totalAZDownloadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_download_size",
		Help: "The total Azure download size as bytes, partial downloads are included",
	})

	// totalAZListObjects is the metric that reports the total successful Azure list objects requests
	totalAZListObjects = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_list_objects",
		Help: "The total number of successful Azure list objects requests",
	})

	// totalAZCopyObject is the metric that reports the total successful Azure copy object requests
	totalAZCopyObject = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_copy_object",
		Help: "The total number of successful Azure copy object requests",
	})

	// totalAZDeleteObject is the metric that reports the total successful Azure delete object requests
	totalAZDeleteObject = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_delete_object",
		Help: "The total number of successful Azure delete object requests",
	})

	// totalAZListObjectsError is the metric that reports the total Azure list objects errors
	totalAZListObjectsErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_list_objects_errors",
		Help: "The total number of Azure list objects errors",
	})

	// totalAZCopyObjectErrors is the metric that reports the total Azure copy object errors
	totalAZCopyObjectErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_copy_object_errors",
		Help: "The total number of Azure copy object errors",
	})

	// totalAZDeleteObjectErrors is the metric that reports the total Azure delete object errors
	totalAZDeleteObjectErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_delete_object_errors",
		Help: "The total number of Azure delete object errors",
	})

	// totalAZHeadObject is the metric that reports the total successful Azure head object requests
	totalAZHeadObject = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_head_object",
		Help: "The total number of successful Azure head object requests",
	})

	// totalAZHeadObjectErrors is the metric that reports the total Azure head object errors
	totalAZHeadObjectErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_head_object_errors",
		Help: "The total number of Azure head object errors",
	})

	// totalAZHeadContainer is the metric that reports the total successful Azure head container requests
	totalAZHeadContainer = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_head_container",
		Help: "The total number of successful Azure head container requests",
	})

	// totalAZHeadContainerErrors is the metric that reports the total Azure head container errors
	totalAZHeadContainerErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_az_head_container_errors",
		Help: "The total number of Azure head container errors",
	})
)

// AddMetricsEndpoint exposes metrics to the specified endpoint
func AddMetricsEndpoint(metricsPath string, handler chi.Router) {
	handler.Handle(metricsPath, promhttp.Handler())
}

// TransferCompleted updates metrics after an upload or a download
func TransferCompleted(bytesSent, bytesReceived int64, transferKind int, err error) {
	if transferKind == 0 {
		// upload
		if err == nil {
			totalUploads.Inc()
		} else {
			totalUploadErrors.Inc()
		}
	} else {
		// download
		if err == nil {
			totalDownloads.Inc()
		} else {
			totalDownloadErrors.Inc()
		}
	}
	if bytesReceived > 0 {
		totalUploadSize.Add(float64(bytesReceived))
	}
	if bytesSent > 0 {
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

// S3HeadObjectCompleted updates metrics after a S3 head object request terminates
func S3HeadObjectCompleted(err error) {
	if err == nil {
		totalS3HeadObject.Inc()
	} else {
		totalS3HeadObjectErrors.Inc()
	}
}

// S3HeadBucketCompleted updates metrics after a S3 head bucket request terminates
func S3HeadBucketCompleted(err error) {
	if err == nil {
		totalS3HeadBucket.Inc()
	} else {
		totalS3HeadBucketErrors.Inc()
	}
}

// GCSTransferCompleted updates metrics after a GCS upload or a download
func GCSTransferCompleted(bytes int64, transferKind int, err error) {
	if transferKind == 0 {
		// upload
		if err == nil {
			totalGCSUploads.Inc()
		} else {
			totalGCSUploadErrors.Inc()
		}
		totalGCSUploadSize.Add(float64(bytes))
	} else {
		// download
		if err == nil {
			totalGCSDownloads.Inc()
		} else {
			totalGCSDownloadErrors.Inc()
		}
		totalGCSDownloadSize.Add(float64(bytes))
	}
}

// GCSListObjectsCompleted updates metrics after a GCS list objects request terminates
func GCSListObjectsCompleted(err error) {
	if err == nil {
		totalGCSListObjects.Inc()
	} else {
		totalGCSListObjectsErrors.Inc()
	}
}

// GCSCopyObjectCompleted updates metrics after a GCS copy object request terminates
func GCSCopyObjectCompleted(err error) {
	if err == nil {
		totalGCSCopyObject.Inc()
	} else {
		totalGCSCopyObjectErrors.Inc()
	}
}

// GCSDeleteObjectCompleted updates metrics after a GCS delete object request terminates
func GCSDeleteObjectCompleted(err error) {
	if err == nil {
		totalGCSDeleteObject.Inc()
	} else {
		totalGCSDeleteObjectErrors.Inc()
	}
}

// GCSHeadObjectCompleted updates metrics after a GCS head object request terminates
func GCSHeadObjectCompleted(err error) {
	if err == nil {
		totalGCSHeadObject.Inc()
	} else {
		totalGCSHeadObjectErrors.Inc()
	}
}

// GCSHeadBucketCompleted updates metrics after a GCS head bucket request terminates
func GCSHeadBucketCompleted(err error) {
	if err == nil {
		totalGCSHeadBucket.Inc()
	} else {
		totalGCSHeadBucketErrors.Inc()
	}
}

// AZTransferCompleted updates metrics after a Azure upload or a download
func AZTransferCompleted(bytes int64, transferKind int, err error) {
	if transferKind == 0 {
		// upload
		if err == nil {
			totalAZUploads.Inc()
		} else {
			totalAZUploadErrors.Inc()
		}
		totalAZUploadSize.Add(float64(bytes))
	} else {
		// download
		if err == nil {
			totalAZDownloads.Inc()
		} else {
			totalAZDownloadErrors.Inc()
		}
		totalAZDownloadSize.Add(float64(bytes))
	}
}

// AZListObjectsCompleted updates metrics after a Azure list objects request terminates
func AZListObjectsCompleted(err error) {
	if err == nil {
		totalAZListObjects.Inc()
	} else {
		totalAZListObjectsErrors.Inc()
	}
}

// AZCopyObjectCompleted updates metrics after a Azure copy object request terminates
func AZCopyObjectCompleted(err error) {
	if err == nil {
		totalAZCopyObject.Inc()
	} else {
		totalAZCopyObjectErrors.Inc()
	}
}

// AZDeleteObjectCompleted updates metrics after a Azure delete object request terminates
func AZDeleteObjectCompleted(err error) {
	if err == nil {
		totalAZDeleteObject.Inc()
	} else {
		totalAZDeleteObjectErrors.Inc()
	}
}

// AZHeadObjectCompleted updates metrics after a Azure head object request terminates
func AZHeadObjectCompleted(err error) {
	if err == nil {
		totalAZHeadObject.Inc()
	} else {
		totalAZHeadObjectErrors.Inc()
	}
}

// AZHeadContainerCompleted updates metrics after a Azure head container request terminates
func AZHeadContainerCompleted(err error) {
	if err == nil {
		totalAZHeadContainer.Inc()
	} else {
		totalAZHeadContainerErrors.Inc()
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
	case loginMethodPublicKey:
		totalKeyLoginAttempts.Inc()
	case loginMethodKeyboardInteractive:
		totalInteractiveLoginAttempts.Inc()
	case loginMethodKeyAndPassword:
		totalKeyAndPasswordLoginAttempts.Inc()
	case loginMethodKeyAndKeyboardInt:
		totalKeyAndKeyIntLoginAttempts.Inc()
	case loginMethodTLSCertificate:
		totalTLSCertLoginAttempts.Inc()
	case loginMethodTLSCertificateAndPwd:
		totalTLSCertAndPwdLoginAttempts.Inc()
	case loginMethodIDP:
		totalIDPLoginAttempts.Inc()
	default:
		totalPasswordLoginAttempts.Inc()
	}
}

func incLoginOK(authMethod string) {
	totalLoginOK.Inc()
	switch authMethod {
	case loginMethodPublicKey:
		totalKeyLoginOK.Inc()
	case loginMethodKeyboardInteractive:
		totalInteractiveLoginOK.Inc()
	case loginMethodKeyAndPassword:
		totalKeyAndPasswordLoginOK.Inc()
	case loginMethodKeyAndKeyboardInt:
		totalKeyAndKeyIntLoginOK.Inc()
	case loginMethodTLSCertificate:
		totalTLSCertLoginOK.Inc()
	case loginMethodTLSCertificateAndPwd:
		totalTLSCertAndPwdLoginOK.Inc()
	case loginMethodIDP:
		totalIDPLoginOK.Inc()
	default:
		totalPasswordLoginOK.Inc()
	}
}

func incLoginFailed(authMethod string) {
	totalLoginFailed.Inc()
	switch authMethod {
	case loginMethodPublicKey:
		totalKeyLoginFailed.Inc()
	case loginMethodKeyboardInteractive:
		totalInteractiveLoginFailed.Inc()
	case loginMethodKeyAndPassword:
		totalKeyAndPasswordLoginFailed.Inc()
	case loginMethodKeyAndKeyboardInt:
		totalKeyAndKeyIntLoginFailed.Inc()
	case loginMethodTLSCertificate:
		totalTLSCertLoginFailed.Inc()
	case loginMethodTLSCertificateAndPwd:
		totalTLSCertAndPwdLoginFailed.Inc()
	case loginMethodIDP:
		totalIDPLoginFailed.Inc()
	default:
		totalPasswordLoginFailed.Inc()
	}
}

// AddLoginResult increments the metrics for login results
func AddLoginResult(authMethod string, err error) {
	if err == nil {
		incLoginOK(authMethod)
	} else {
		incLoginFailed(authMethod)
	}
}

// AddNoAuthTryed increments the metric for clients disconnected
// for inactivity before trying to login
func AddNoAuthTryed() {
	totalNoAuthTryed.Inc()
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
