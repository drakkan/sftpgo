# Running SFTPGo as a service

## Linux

For Linux, a `systemd` sample [service](../init/sftpgo.service "systemd service") can be found inside the source tree.

## macOS

For macOS, a `launchd` sample [service](../init/com.github.drakkan.sftpgo.plist "launchd plist") can be found inside the source tree. The `launchd` plist assumes that SFTPGo has `/usr/local/opt/sftpgo` as base directory.

## Windows

On Windows, you can register SFTPGo as Windows Service. Take a look at the CLI usage to learn how to do this:

```powershell
PS> sftpgo.exe service --help
Install, Uninstall, Start, Stop, Reload and retrieve status for SFTPGo Windows Service

Usage:
  sftpgo service [command]

Available Commands:
  install     Install SFTPGo as Windows Service
  reload      Reload the SFTPGo Windows Service sending a `paramchange` request
  start       Start SFTPGo Windows Service
  status      Retrieve the status for the SFTPGo Windows Service
  stop        Stop SFTPGo Windows Service
  uninstall   Uninstall SFTPGo Windows Service

Flags:
  -h, --help   help for service

Use "sftpgo service [command] --help" for more information about a command.
```

The `install` subcommand accepts the same flags that are valid for `serve`.

After installing as a Windows Service, please remember to allow network access to the SFTPGo executable using something like this:

```powershell
PS> netsh advfirewall firewall add rule name="SFTPGo Service" dir=in action=allow program="C:\Program Files\SFTPGo\sftpgo.exe"
```

(Or through the Windows Firewall GUI.)
