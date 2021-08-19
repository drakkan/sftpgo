//go:build nopgsql
// +build nopgsql

package dataprovider

import (
	"errors"

	"github.com/drakkan/sftpgo/v2/version"
)

func init() {
	version.AddFeature("-pgsql")
}

func initializePGSQLProvider() error {
	return errors.New("PostgreSQL disabled at build time")
}
