// Full featured and highly configurable SFTP server.
// For more details about features, installation, configuration and usage please refer to the README inside the source tree:
// https://github.com/drakkan/sftpgo/blob/master/README.md
package main // import "github.com/drakkan/sftpgo"

import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"github.com/drakkan/sftpgo/cmd"
)

func main() {
	cmd.Execute()
}
