//go:build windows

package plugin

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	hostJobOnce sync.Once
	hostJob     windows.Handle
	hostJobErr  error
)

// tieProcessToHost assigns the process to a job object that kills its processes
// when the last handle to it is closed. The handle is held for the lifetime of
// SFTPGo and is not inheritable, so Windows closes it, and kills the plugins,
// however SFTPGo exits.
func tieProcessToHost(pid int) error {
	hostJobOnce.Do(func() {
		hostJob, hostJobErr = newKillOnCloseJob()
	})
	if hostJobErr != nil {
		return hostJobErr
	}
	return assignToJob(hostJob, pid)
}

func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("create job object: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("set job object limits: %w", err)
	}
	return job, nil
}

func assignToJob(job windows.Handle, pid int) error {
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("open process: %w", err)
	}
	defer windows.CloseHandle(process)

	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return fmt.Errorf("assign process to job object: %w", err)
	}
	return nil
}
