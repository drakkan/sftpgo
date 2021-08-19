//go:build nometrics
// +build nometrics

package metric

import (
	"github.com/go-chi/chi/v5"

	"github.com/drakkan/sftpgo/v2/version"
)

func init() {
	version.AddFeature("-metrics")
}

// AddMetricsEndpoint exposes metrics to the specified endpoint
func AddMetricsEndpoint(metricsPath string, handler chi.Router) {}

// TransferCompleted updates metrics after an upload or a download
func TransferCompleted(bytesSent, bytesReceived int64, transferKind int, err error) {}

// S3TransferCompleted updates metrics after an S3 upload or a download
func S3TransferCompleted(bytes int64, transferKind int, err error) {}

// S3ListObjectsCompleted updates metrics after an S3 list objects request terminates
func S3ListObjectsCompleted(err error) {}

// S3CopyObjectCompleted updates metrics after an S3 copy object request terminates
func S3CopyObjectCompleted(err error) {}

// S3DeleteObjectCompleted updates metrics after an S3 delete object request terminates
func S3DeleteObjectCompleted(err error) {}

// S3HeadBucketCompleted updates metrics after an S3 head bucket request terminates
func S3HeadBucketCompleted(err error) {}

// GCSTransferCompleted updates metrics after a GCS upload or a download
func GCSTransferCompleted(bytes int64, transferKind int, err error) {}

// GCSListObjectsCompleted updates metrics after a GCS list objects request terminates
func GCSListObjectsCompleted(err error) {}

// GCSCopyObjectCompleted updates metrics after a GCS copy object request terminates
func GCSCopyObjectCompleted(err error) {}

// GCSDeleteObjectCompleted updates metrics after a GCS delete object request terminates
func GCSDeleteObjectCompleted(err error) {}

// GCSHeadBucketCompleted updates metrics after a GCS head bucket request terminates
func GCSHeadBucketCompleted(err error) {}

// SSHCommandCompleted update metrics after an SSH command terminates
func SSHCommandCompleted(err error) {}

// UpdateDataProviderAvailability updates the metric for the data provider availability
func UpdateDataProviderAvailability(err error) {}

// AddLoginAttempt increments the metrics for login attempts
func AddLoginAttempt(authMethod string) {}

// AddLoginResult increments the metrics for login results
func AddLoginResult(authMethod string, err error) {}

// AddNoAuthTryed increments the metric for clients disconnected
// for inactivity before trying to login
func AddNoAuthTryed() {}

// HTTPRequestServed increments the metrics for HTTP requests
func HTTPRequestServed(status int) {}

// UpdateActiveConnectionsSize sets the metric for active connections
func UpdateActiveConnectionsSize(size int) {}
