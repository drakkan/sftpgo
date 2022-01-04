// Fully featured and highly configurable SFTP server with optional
// FTP/S and WebDAV support.
// For more details about features, installation, configuration and usage
// please refer to the README inside the source tree:
// https://github.com/drakkan/sftpgo/blob/main/README.md
package main // import "github.com/drakkan/sftpgo"

import (
	"fmt"

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/drakkan/sftpgo/v2/cmd"
)

func main() {
	if undo, err := maxprocs.Set(); err != nil {
		fmt.Printf("error setting max procs: %v\n", err)
		undo()
	}
	cmd.Execute()
}
