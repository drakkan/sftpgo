// +build nosqlite

package dataprovider

import (
	"errors"

	"github.com/drakkan/sftpgo/utils"
)

func init() {
	utils.AddFeature("-sqlite")
}

func initializeSQLiteProvider(basePath string) error {
	return errors.New("SQLite disabled at build time")
}
