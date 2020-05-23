// +build nopgsql

package dataprovider

import (
	"errors"

	"github.com/drakkan/sftpgo/utils"
)

func init() {
	utils.AddFeature("-pgsql")
}

func initializePGSQLProvider() error {
	return errors.New("PostgreSQL disabled at build time")
}
