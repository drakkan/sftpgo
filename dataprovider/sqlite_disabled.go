//go:build nosqlite
// +build nosqlite

package dataprovider

import (
	"errors"

	"github.com/drakkan/sftpgo/v2/version"
)

func init() {
	version.AddFeature("-sqlite")
}

func initializeSQLiteProvider(basePath string) error {
	return errors.New("SQLite disabled at build time")
}
