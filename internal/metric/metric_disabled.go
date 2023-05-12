//go:build nometrics
// +build nometrics

package metric

import (
	"github.com/go-chi/chi/v5"

	"github.com/drakkan/sftpgo/v2/internal/version"
)

func init() {
	version.AddFeature("-metrics")
}

// AddMetricsEndpoint publishes metrics to the specified endpoint
func AddMetricsEndpoint(_ string, _ chi.Router) {}

// TransferCompleted updates metrics after an upload or a download
func TransferCompleted(_, _ int64, _ int, _ error, _ bool) {}

// S3TransferCompleted updates metrics after an S3 upload or a download
func S3TransferCompleted(_ int64, _ int, _ error) {}

// S3ListObjectsCompleted updates metrics after an S3 list objects request terminates
func S3ListObjectsCompleted(_ error) {}

// S3CopyObjectCompleted updates metrics after an S3 copy object request terminates
func S3CopyObjectCompleted(_ error) {}

// S3DeleteObjectCompleted updates metrics after an S3 delete object request terminates
func S3DeleteObjectCompleted(_ error) {}

// S3HeadBucketCompleted updates metrics after an S3 head bucket request terminates
func S3HeadBucketCompleted(_ error) {}

// GCSTransferCompleted updates metrics after a GCS upload or a download
func GCSTransferCompleted(_ int64, _ int, _ error) {}

// GCSListObjectsCompleted updates metrics after a GCS list objects request terminates
func GCSListObjectsCompleted(_ error) {}

// GCSCopyObjectCompleted updates metrics after a GCS copy object request terminates
func GCSCopyObjectCompleted(_ error) {}

// GCSDeleteObjectCompleted updates metrics after a GCS delete object request terminates
func GCSDeleteObjectCompleted(_ error) {}

// GCSHeadBucketCompleted updates metrics after a GCS head bucket request terminates
func GCSHeadBucketCompleted(_ error) {}

// HTTPFsTransferCompleted updates metrics after an HTTPFs upload or a download
func HTTPFsTransferCompleted(_ int64, _ int, _ error) {}

// SSHCommandCompleted update metrics after an SSH command terminates
func SSHCommandCompleted(_ error) {}

// UpdateDataProviderAvailability updates the metric for the data provider availability
func UpdateDataProviderAvailability(_ error) {}

// AddLoginAttempt increments the metrics for login attempts
func AddLoginAttempt(_ string) {}

// AddLoginResult increments the metrics for login results
func AddLoginResult(_ string, _ error) {}

// AddNoAuthTried increments the metric for clients disconnected
// for inactivity before trying to login
func AddNoAuthTried() {}

// HTTPRequestServed increments the metrics for HTTP requests
func HTTPRequestServed(_ int) {}

// UpdateActiveConnectionsSize sets the metric for active connections
func UpdateActiveConnectionsSize(_ int) {}
