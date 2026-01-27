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

//go:build nometrics

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
func TransferCompleted(_, _ int64, _ int, _ error, _ bool, _ string) {}

// S3TransferCompleted updates metrics after an S3 upload or a download
func S3TransferCompleted(_ int64, _ int, _ error, _ string) {}

// S3ListObjectsCompleted updates metrics after an S3 list objects request terminates
func S3ListObjectsCompleted(_ error, _ string) {}

// S3CopyObjectCompleted updates metrics after an S3 copy object request terminates
func S3CopyObjectCompleted(_ error, _ string) {}

// S3DeleteObjectCompleted updates metrics after an S3 delete object request terminates
func S3DeleteObjectCompleted(_ error, _ string) {}

// S3HeadObjectCompleted updates metrics after an S3 head object request terminates
func S3HeadObjectCompleted(_ error, _ string) {}

// GCSTransferCompleted updates metrics after a GCS upload or a download
func GCSTransferCompleted(_ int64, _ int, _ error, _ string) {}

// GCSListObjectsCompleted updates metrics after a GCS list objects request terminates
func GCSListObjectsCompleted(_ error, _ string) {}

// GCSCopyObjectCompleted updates metrics after a GCS copy object request terminates
func GCSCopyObjectCompleted(_ error, _ string) {}

// GCSDeleteObjectCompleted updates metrics after a GCS delete object request terminates
func GCSDeleteObjectCompleted(_ error, _ string) {}

// GCSHeadObjectCompleted updates metrics after a GCS head object request terminates
func GCSHeadObjectCompleted(_ error, _ string) {}

// AZTransferCompleted updates metrics after an Azure upload or a download
func AZTransferCompleted(_ int64, _ int, _ error, _ string) {}

// AZListObjectsCompleted updates metrics after an Azure list objects request terminates
func AZListObjectsCompleted(_ error, _ string) {}

// AZCopyObjectCompleted updates metrics after an Azure copy object request terminates
func AZCopyObjectCompleted(_ error, _ string) {}

// AZDeleteObjectCompleted updates metrics after an Azure delete object request terminates
func AZDeleteObjectCompleted(_ error, _ string) {}

// AZHeadObjectCompleted updates metrics after an Azure head object request terminates
func AZHeadObjectCompleted(_ error, _ string) {}

// HTTPFsTransferCompleted updates metrics after an HTTPFs upload or a download
func HTTPFsTransferCompleted(_ int64, _ int, _ error, _ string) {}

// SSHCommandCompleted update metrics after an SSH command terminates
func SSHCommandCompleted(_ error, _ string) {}

// UpdateDataProviderAvailability updates the metric for the data provider availability
func UpdateDataProviderAvailability(_ error) {}

// AddLoginAttempt increments the metrics for login attempts
func AddLoginAttempt(_ string, _ string) {}

// AddLoginResult increments the metrics for login results
func AddLoginResult(_ string, _ error, _ string) {}

// AddNoAuthTried increments the metric for clients disconnected
// for inactivity before trying to login
func AddNoAuthTried() {}

// HTTPRequestServed increments the metrics for HTTP requests
func HTTPRequestServed(_ int) {}

// UpdateActiveConnectionsSize sets the metric for active connections
func UpdateActiveConnectionsSize(_ int, _ string) {}
