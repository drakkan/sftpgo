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

//go:build !nopgsql

package dataprovider

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	rdsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"
)

var (
	pgsqlAWSConfig     aws.Config
	pgsqlAWSConfigErr  error
	pgsqlAWSConfigOnce sync.Once
)

// getPGSQLAWSConfig returns the AWS SDK configuration used to generate RDS/Aurora
// IAM authentication tokens. The default credentials chain is resolved only once,
// on first use, and then reused for the whole provider lifetime instead of being
// re-resolved for each new connection
func getPGSQLAWSConfig(ctx context.Context) (aws.Config, error) {
	pgsqlAWSConfigOnce.Do(func() {
		pgsqlAWSConfig, pgsqlAWSConfigErr = awsconfig.LoadDefaultConfig(ctx)
	})
	return pgsqlAWSConfig, pgsqlAWSConfigErr
}

// getPGSQLAWSIAMToken returns a freshly generated IAM authentication token to use
// as the password for a new connection to a postgres compatible AWS RDS/Aurora
// database. Unlike the underlying AWS configuration, these tokens are short-lived
// and so must be generated again for each new physical connection
func getPGSQLAWSIAMToken(ctx context.Context, host string, port uint16, user string) (string, error) {
	awsCfg, err := getPGSQLAWSConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to get AWS config: %w", err)
	}
	endpoint := fmt.Sprintf("%s:%d", host, port)
	return rdsauth.BuildAuthToken(ctx, endpoint, awsCfg.Region, user, awsCfg.Credentials)
}
