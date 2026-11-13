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

package plugin

import (
	"os/exec"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

// tieToHost makes the started plugin process end together with the SFTPGo
// process. A failure is logged and the plugin keeps running.
func tieToHost(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := tieProcessToHost(cmd.Process.Pid); err != nil {
		logger.Warn(logSender, "", "unable to tie plugin process %q, pid %d, to the SFTPGo process: %v",
			cmd.Path, cmd.Process.Pid, err)
	}
}
