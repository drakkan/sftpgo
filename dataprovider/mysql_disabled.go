// +build nomysql

package dataprovider

import (
	"errors"

	"github.com/drakkan/sftpgo/utils"
)

func init() {
	utils.AddFeature("-mysql")
}

func initializeMySQLProvider() error {
	return errors.New("MySQL disabled at build time")
}
