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
	"github.com/shirou/gopsutil/v3/process"

	"github.com/drakkan/sftpgo/v2/internal/logger"
)

func killProcess(processPath string) {
	procs, err := process.Processes()
	if err != nil {
		return
	}
	for _, p := range procs {
		cmdLine, err := p.Exe()
		if err == nil {
			if cmdLine == processPath {
				err = p.Kill()
				logger.Debug(logSender, "", "killed process %v, pid %v, err %v", cmdLine, p.Pid, err)
				return
			}
		}
	}
	logger.Debug(logSender, "", "no match for plugin process %v", processPath)
}
