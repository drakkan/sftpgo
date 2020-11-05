# SFTP subsystem mode

In this mode SFTPGo speaks the server side of SFTP protocol to stdout and expects client requests from stdin.
You can use SFTPGo as subsystem via the `startsubsys` command.
This mode is not intended to be called directly, but from sshd using the `Subsystem` option.
For example adding a line like this one in `/etc/ssh/sshd_config`:

```shell
Subsystem    sftp    sftpgo startsubsys
```

Command-line flags should be specified in the Subsystem declaration.

```shell
Usage:
  sftpgo startsubsys [flags]

Flags:
  -d, --base-home-dir string   If the user does not exist specify an alternate
                               starting directory. The home directory for a new
                               user will be:

                               <base-home-dir>/<username>

                               base-home-dir must be an absolute path.
  -c, --config-dir string      Location for SFTPGo config dir. This directory
                               should contain the "sftpgo" configuration file
                               or the configured config-file and it is used as
                               the base for files with a relative path (eg. the
                               private keys for the SFTP server, the SQLite
                               database if you use SQLite as data provider).
                               This flag can be set using SFTPGO_CONFIG_DIR
                               env var too. (default ".")
  -f, --config-file string     Name for SFTPGo configuration file. It must be
                               the name of a file stored in config-dir not the
                               absolute path to the configuration file. The
                               specified file name must have no extension we
                               automatically load JSON, YAML, TOML, HCL and
                               Java properties. Therefore if you set "sftpgo"
                               then "sftpgo.json", "sftpgo.yaml" and so on
                               are searched.
                               This flag can be set using SFTPGO_CONFIG_FILE
                               env var too. (default "sftpgo")
  -h, --help                   help for startsubsys
  -j, --log-to-journald        Send logs to journald. Only available on Linux.
                               Use:

                               $ journalctl -o verbose -f

                               To see full logs.
                               If not set, the logs will be sent to the standard
                               error
  -v, --log-verbose            Enable verbose logs. This flag can be set
                               using SFTPGO_LOG_VERBOSE env var too.
                                (default true)
  -p, --preserve-home          If the user already exists, the existing home
                               directory will not be changed
```

In this mode `bolt` and `sqlite` providers are not usable as the same database file cannot be shared among multiple processes, if one of these provider is configured it will be automatically changed to `memory` provider.

The username and home directory for the logged in user are determined using [user.Current()](https://golang.org/pkg/os/user/#Current).
If the user who is logging is not found within the SFTPGo data provider, it is added automatically.
You can pre-configure the users inside the SFTPGo data provider, this way you can use a different home directory, restrict permissions and such.
