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

                               [base-home-dir]/[username]

                               base-home-dir must be an absolute path.
  -c, --config-dir string      Location for the config dir. This directory
                               is used as the base for files with a relative
                               path, eg. the private keys for the SFTP
                               server or the SQLite database if you use
                               SQLite as data provider.
                               The configuration file, if not explicitly set,
                               is looked for in this dir. We support reading
                               from JSON, TOML, YAML, HCL, envfile and Java
                               properties config files. The default config
                               file name is "sftpgo" and therefore
                               "sftpgo.json", "sftpgo.yaml" and so on are
                               searched.
                               This flag can be set using SFTPGO_CONFIG_DIR
                               env var too. (default ".")
      --config-file string     Path to SFTPGo configuration file.
                               This flag explicitly defines the path, name
                               and extension of the config file. If must be
                               an absolute path or a path relative to the
                               configuration directory. The specified file
                               name must have a supported extension (JSON,
                               YAML, TOML, HCL or Java properties).
                               This flag can be set using SFTPGO_CONFIG_FILE
                               env var too.
  -h, --help                   help for startsubsys
  -j, --log-to-journald        Send logs to journald. Only available on Linux.
                               Use:

                               $ journalctl -o verbose -f

                               To see full logs.
                               If not set, the logs will be sent to the standard
                               error
      --log-utc-time           Use UTC time for logging. This flag can be set
                               using SFTPGO_LOG_UTC_TIME env var too.
                                (default true)
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
