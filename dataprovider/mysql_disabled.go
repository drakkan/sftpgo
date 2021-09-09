//go:build nomysql
// +build nomysql

package dataprovider

import (
	"errors"

	"github.com/drakkan/sftpgo/version"
)

func init() {
	version.AddFeature("-mysql")
}

func initializeMySQLProvider() error {
	return errors.New("MySQL disabled at build time")
}
