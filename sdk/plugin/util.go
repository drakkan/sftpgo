package plugin

import (
	"github.com/shirou/gopsutil/v3/process"

	"github.com/drakkan/sftpgo/v2/logger"
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
