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

// Fully featured and highly configurable SFTP server with optional
// FTP/S and WebDAV support.
// For more details about features, installation, configuration and usage
// please refer to the README inside the source tree:
// https://github.com/drakkan/sftpgo/blob/main/README.md
package main // import "github.com/drakkan/sftpgo"

import (
	"fmt"

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/drakkan/sftpgo/v2/internal/cmd"
)

func main() {
	if undo, err := maxprocs.Set(); err != nil {
		fmt.Printf("error setting max procs: %v\n", err)
		undo()
	}
	cmd.Execute()
}
