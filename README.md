# SFTPGo
[![Build Status](https://travis-ci.org/drakkan/sftpgo.svg?branch=master)](https://travis-ci.org/drakkan/sftpgo) [![Code Coverage](https://codecov.io/gh/drakkan/sftpgo/branch/master/graph/badge.svg)](https://codecov.io/gh/drakkan/sftpgo/branch/master) [![Go Report Card](https://goreportcard.com/badge/github.com/drakkan/sftpgo)](https://goreportcard.com/report/github.com/drakkan/sftpgo) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0) [![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

Full featured and highly configurable SFTP server

## Features

- Each account is chrooted to his Home Dir.
- SFTP accounts are virtual accounts stored in a "data provider".
- SQLite, MySQL, PostgreSQL, bbolt (key/value store in pure Go) and in memory data providers are supported.
- Public key and password authentication. Multiple public keys per user are supported.
- Keyboard interactive authentication. You can easily setup a customizable multi-factor authentication.
- Per user authentication methods. You can, for example, deny one or more authentication methods to one or more users.
- Custom authentication via external programs is supported.
- Dynamic user modification before login via external programs is supported.
- Quota support: accounts can have individual quota expressed as max total size and/or max number of files.
- Bandwidth throttling is supported, with distinct settings for upload and download.
- Per user maximum concurrent sessions.
- Per user and per directory permission management: list directory contents, upload, overwrite, download, delete, rename, create directories, create symlinks, change owner/group and mode, change access and modification times.
- Per user files/folders ownership mapping: you can map all the users to the system account that runs SFTPGo (all platforms are supported) or you can run SFTPGo as root user and map each user or group of users to a different system account (*NIX only).
- Per user IP filters are supported: login can be restricted to specific ranges of IP addresses or to a specific IP address.
- Per user and per directory file extensions filters are supported: files can be allowed or denied based on their extensions.
- Virtual folders are supported: directories outside the user home directory can be exposed as virtual folders.
- Configurable custom commands and/or HTTP notifications on file upload, download, delete, rename, on SSH commands and on user add, update and delete.
- Automatically terminating idle connections.
- Atomic uploads are configurable.
- Support for Git repositories over SSH.
- SCP and rsync are supported.
- Support for serving local filesystem, S3 Compatible Object Storage and Google Cloud Storage over SFTP/SCP.
- Prometheus metrics are exposed.
- Support for HAProxy PROXY protocol: you can proxy and/or load balance the SFTP/SCP service without losing the information about the client's address.
- REST API for users management, backup, restore and real time reports of the active connections with possibility of forcibly closing a connection.
- Web based interface to easily manage users and connections.
- Easy migration from Linux system user accounts.
- Portable mode: a convenient way to share a single directory on demand.
- Configuration format is at your choice: JSON, TOML, YAML, HCL, envfile are supported.
- Log files are accurate and they are saved in the easily parsable JSON format.

## Platforms

SFTPGo is developed and tested on Linux. After each commit the code is automatically built and tested on Linux and macOS using Travis CI.
The test cases are regularly manually executed and passed on Windows. Other UNIX variants such as *BSD should work too.

## Requirements

- Go 1.13 or higher as build only dependency.
- A suitable SQL server or key/value store to use as data provider: PostreSQL 9.4+ or MySQL 5.6+ or SQLite 3.x or bbolt 1.3.x

## Installation

Binary releases for Linux, macOS and Windows are available, please visit the [releases](https://github.com/drakkan/sftpgo/releases "releases") page.

Sample Dockerfiles for [Debian](https://www.debian.org "Debian") and [Alpine](https://alpinelinux.org "Alpine") are available inside the source tree [docker](./docker "docker") directory.

Some Linux distro packages are available:

- For Arch Linux via AUR:
  - [sftpgo](https://aur.archlinux.org/packages/sftpgo/). This package follow stable releases. It requires `git`, `gcc` and `go` to build.
  - [sftpgo-bin](https://aur.archlinux.org/packages/sftpgo-bin/). This package follow stable releases downloading the prebuilt linux binary from GitHub. It does not require `git`, `gcc` and `go` to build.
  - [sftpgo-git](https://aur.archlinux.org/packages/sftpgo-git/). This package build and install the latest git master. It requires `git`, `gcc` and `go` to build.

Alternately you can install the package to your [$GOPATH](https://github.com/golang/go/wiki/GOPATH "GOPATH") with the [go tool](https://golang.org/cmd/go/ "go command") from shell:

```
$ go get -u github.com/drakkan/sftpgo
```

Make sure [Git](https://git-scm.com/downloads) is installed on your machine and in your system's `PATH`.

SFTPGo depends on [go-sqlite3](https://github.com/mattn/go-sqlite3) which is a CGO package and so it requires a `C` compiler at build time.
On Linux and macOS a compiler is easy to install or already installed, on Windows you need to download [MinGW-w64](https://sourceforge.net/projects/mingw-w64/files/) and build SFTPGo from its command prompt.

The compiler is a build time only dependency, it is not not required at runtime.

If you don't need SQLite, you can also get/build SFTPGo setting the environment variable `GCO_ENABLED` to 0, this way SQLite support will be disabled and PostgreSQL, MySQL, bbolt and memory data providers will keep working, in this way you don't need a `C` compiler for building.

Version info, such as git commit and build date, can be embedded setting the following string variables at build time:

- `github.com/drakkan/sftpgo/utils.commit`
- `github.com/drakkan/sftpgo/utils.date`

For example you can build using the following command:

```
go build -i -ldflags "-s -w -X github.com/drakkan/sftpgo/utils.commit=`git describe --always --dirty` -X github.com/drakkan/sftpgo/utils.date=`date -u +%FT%TZ`" -o sftpgo
```

and you will get a version that includes git commit and build date like this one:

```
sftpgo -v
SFTPGo version: 0.9.0-dev-90607d4-dirty-2019-08-08T19:28:36Z
```

For Linux, a `systemd` sample [service](./init/sftpgo.service "systemd service") can be found inside the source tree.

For macOS a `launchd` sample [service](./init/com.github.drakkan.sftpgo.plist "launchd plist") can be found inside the source tree. The `launchd` plist assumes that `sftpgo` has `/usr/local/opt/sftpgo` as base directory.

On Windows you can run `SFTPGo` as Windows Service, please read the "Configuration" section below for more details.

## Configuration

The `sftpgo` executable can be used this way:

```
Usage:
  sftpgo [command]

Available Commands:
  help         Help about any command
  initprovider Initializes the configured data provider
  portable     Serve a single directory
  serve        Start the SFTP Server

Flags:
  -h, --help      help for sftpgo
  -v, --version

 Use "sftpgo [command] --help" for more information about a command
```

The `serve` command supports the following flags:

- `--config-dir` string. Location of the config dir. This directory should contain the `sftpgo` configuration file and is used as the base directory for files with a relative path (eg. the private keys for the SFTP server, the SQLite or bblot database if you use SQLite or bbolt as data provider). The default value is "." or the value of `SFTPGO_CONFIG_DIR` environment variable.
- `--config-file` string. Name of the configuration file. It must be the name of a file stored in `config-dir` not the absolute path to the configuration file. The specified file name must have no extension we automatically load JSON, YAML, TOML, HCL and Java properties. The default value is "sftpgo" (and therefore `sftpgo.json`, `sftpgo.yaml` and so on are searched) or the value of `SFTPGO_CONFIG_FILE` environment variable.
- `--log-compress` boolean. Determine if the rotated log files should be compressed using gzip. Default `false` or the value of `SFTPGO_LOG_COMPRESS` environment variable (1 or `true`, 0 or `false`). It is unused if `log-file-path` is empty.
- `--log-file-path` string. Location for the log file, default "sftpgo.log" or the value of `SFTPGO_LOG_FILE_PATH` environment variable. Leave empty to write logs to the standard error.
- `--log-max-age` int. Maximum number of days to retain old log files. Default 28 or the value of `SFTPGO_LOG_MAX_AGE` environment variable. It is unused if `log-file-path` is empty.
- `--log-max-backups` int. Maximum number of old log files to retain. Default 5 or the value of `SFTPGO_LOG_MAX_BACKUPS` environment variable. It is unused if `log-file-path` is empty.
- `--log-max-size` int. Maximum size in megabytes of the log file before it gets rotated. Default 10 or the value of `SFTPGO_LOG_MAX_SIZE` environment variable. It is unused if `log-file-path` is empty.
- `--log-verbose` boolean. Enable verbose logs. Default `true` or the value of `SFTPGO_LOG_VERBOSE` environment variable (1 or `true`, 0 or `false`).

If you don't configure any private host key, the daemon will use `id_rsa` and `id_ecdsa` in the configuration directory. If these files don't exist, the daemon will attempt to autogenerate them (if the user that executes SFTPGo has write access to the `config-dir`). The server supports any private key format supported by [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/keys.go#L33).

The `sftpgo` configuration file contains the following sections:

- **"sftpd"**, the configuration for the SFTP server
    - `bind_port`, integer. The port used for serving SFTP requests. Default: 2022
    - `bind_address`, string. Leave blank to listen on all available network interfaces. Default: ""
    - `idle_timeout`, integer. Time in minutes after which an idle client will be disconnected. 0 means disabled. Default: 15
    - `max_auth_tries` integer. Maximum number of authentication attempts permitted per connection. If set to a negative number, the number of attempts is unlimited. If set to zero, the number of attempts are limited to 6.
    - `umask`, string. Umask for the new files and directories. This setting has no effect on Windows. Default: "0022"
    - `banner`, string. Identification string used by the server. Leave empty to use the default banner. Default `SFTPGo_<version>`, for example `SSH-2.0-SFTPGo_0.9.5`
    - `upload_mode` integer. 0 means standard, the files are uploaded directly to the requested path. 1 means atomic: files are uploaded to a temporary path and renamed to the requested path when the client ends the upload. Atomic mode avoids problems such as a web server that serves partial files when the files are being uploaded. In atomic mode if there is an upload error the temporary file is deleted and so the requested upload path will not contain a partial file. 2 means atomic with resume support: as atomic but if there is an upload error the temporary file is renamed to the requested path and not deleted, this way a client can reconnect and resume the upload.
    - `actions`, struct. It contains the command to execute and/or the HTTP URL to notify and the trigger conditions. See the "Custom Actions" paragraph for more details
        - `execute_on`, list of strings. Valid values are `download`, `upload`, `delete`, `rename`, `ssh_cmd`. Leave empty to disable actions.
        - `command`, string. Absolute path to the command to execute. Leave empty to disable.
        - `http_notification_url`, a valid URL. An HTTP GET request will be executed to this URL. Leave empty to disable.
    - `keys`, struct array. It contains the daemon's private keys. If empty or missing the daemon will search or try to generate `id_rsa` and `id_ecdsa` keys in the configuration directory.
        - `private_key`, path to the private key file. It can be a path relative to the config dir or an absolute one.
    - `enable_scp`, boolean. Default disabled. Set to `true` to enable the experimental SCP support. This setting is deprecated and will be removed in future versions, please add `scp` to the `enabled_ssh_commands` list to enable it
    - `kex_algorithms`, list of strings. Available KEX (Key Exchange) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L46 "Supported kex algos")
    - `ciphers`, list of strings. Allowed ciphers. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L28 "Supported ciphers")
    - `macs`, list of strings. available MAC (message authentication code) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L84 "Supported MACs")
    - `login_banner_file`, path to the login banner file. The contents of the specified file, if any, are sent to the remote user before authentication is allowed. It can be a path relative to the config dir or an absolute one. Leave empty to disable login banner
    - `setstat_mode`, integer. 0 means "normal mode": requests for changing permissions, owner/group and access/modification times are executed. 1 means "ignore mode": requests for changing permissions, owner/group and access/modification times are silently ignored.
    - `enabled_ssh_commands`, list of enabled SSH commands. These SSH commands are enabled by default: `md5sum`, `sha1sum`, `cd`, `pwd`. `*` enables all supported commands. Some commands are implemented directly inside SFTPGo, while for other commands we use system commands that need to be installed and in your system's `PATH`. For system commands we have no direct control on file creation/deletion and so we cannot support remote filesystems, such as S3, and quota check is suboptimal: if quota is enabled, the number of files is checked at the command begin and not while new files are created. The allowed size is calculated as the difference between the max quota and the used one and it is checked against the bytes transferred via SSH. The command is aborted if it uploads more bytes than the remaining allowed size calculated at the command start. Anyway we see the bytes that the remote command send to the local command via SSH, these bytes contain both protocol commands and files and so the size of the files is different from the size trasferred via SSH: for example a command can send compressed files or a protocol command (few bytes) could delete a big file. To mitigate this issue quotas are recalculated at the command end with a full home directory scan, this could be heavy for big directories. If you need system commands and quotas you could consider to disable quota restrictions and periodically update quota usage yourself using the REST API. We support the following SSH commands:
      - `scp`, SCP is an experimental feature, we have our own SCP implementation since we can't rely on "scp" system command to proper handle quotas and user's home dir restrictions. The SCP protocol is quite simple but there is no official docs about it, so we need more testing and feedbacks before enabling it by default. We may not handle some borderline cases or have sneaky bugs. Please do accurate tests yourself before enabling SCP and let us known if something does not work as expected for your use cases. SCP between two remote hosts is supported using the `-3` scp option.
      - `md5sum`, `sha1sum`, `sha256sum`, `sha384sum`, `sha512sum`. Useful to check message digests for uploaded files. These commands are implemented inside SFTPGo so they work even if the matching system commands are not available, for example on Windows.
      - `cd`, `pwd`. Some SFTP clients does not support the SFTP SSH_FXP_REALPATH packet type and so they use `cd` and `pwd` SSH commands to get the initial directory. Currently `cd` does nothing and `pwd` always returns the `/` path.
      - `git-receive-pack`, `git-upload-pack`, `git-upload-archive`. These commands enable support for Git repositories over SSH, they need to be installed and in your system's `PATH`. Git commands are not allowed inside virtual folders and inside directories with file extensions filters.
      - `rsync`. The `rsync` command need to be installed and in your system's `PATH`. We cannot avoid that rsync creates symlinks so if the user has the permission to create symlinks we add the option `--safe-links` to the received rsync command, if it is not already set. This should prevent to create symlinks that point outside the home dir. If the user cannot create symlinks we add the option `--munge-links`, if it is not already set. This should make symlinks unusable (but manually recoverable). The `rsync` command interacts with the filesystem directly and it is not aware about virtual folders and file extensions filters, so it will be automatically disabled for users with these features enabled.
    - `keyboard_interactive_auth_program`, string. Absolute path to an external program to use for keyboard interactive authentication. See the "Keyboard Interactive Authentication" paragraph for more details.
    - `proxy_protocol`, integer. Support for [HAProxy PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt). If you are running SFTPGo behind a proxy server such as HAProxy, AWS ELB or NGNIX, you can enable the proxy protocol. It provides a convenient way to safely transport connection information such as a client's address across multiple layers of NAT or TCP proxies to get the real client IP address instead of the proxy IP. Both protocol version 1 and 2 are supported. If the proxy protocol is enabled in SFTPGo then you have to enable the protocol in your proxy configuration too, for example for HAProxy add `send-proxy` or `send-proxy-v2` to each server configuration line. The following modes are supported:
      - 0, disabled
      - 1, enabled. Proxy header will be used and requests without proxy header will be accepted
      - 2, required. Proxy header will be used and requests without proxy header will be rejected
    - `proxy_allowed`, List of IP addresses and IP ranges allowed to send the proxy header:
      - If `proxy_protocol` is set to 1 and we receive a proxy header from an IP that is not in the list then the connection will be accepted and the header will be ignored
      - If `proxy_protocol` is set to 2 and we receive a proxy header from an IP that is not in the list then the connection will be rejected
- **"data_provider"**, the configuration for the data provider
    - `driver`, string. Supported drivers are `sqlite`, `mysql`, `postgresql`, `bolt`, `memory`
    - `name`, string. Database name. For driver `sqlite` this can be the database name relative to the config dir or the absolute path to the SQLite database. For driver `memory` this is the (optional) path relative to the config dir or the absolute path to the users dump to load.
    - `host`, string. Database host. Leave empty for drivers `sqlite`, `bolt` and `memory`
    - `port`, integer. Database port. Leave empty for drivers `sqlite`, `bolt` and `memory`
    - `username`, string. Database user. Leave empty for drivers `sqlite`, `bolt` and `memory`
    - `password`, string. Database password. Leave empty for drivers `sqlite`, `bolt` and `memory`
    - `sslmode`, integer. Used for drivers `mysql` and `postgresql`. 0 disable SSL/TLS connections, 1 require ssl, 2 set ssl mode to `verify-ca` for driver `postgresql` and `skip-verify` for driver `mysql`, 3 set ssl mode to `verify-full` for driver `postgresql` and `preferred` for driver `mysql`
    - `connectionstring`, string. Provide a custom database connection string. If not empty this connection string will be used instead of build one using the previous parameters. Leave empty for drivers `bolt` and `memory`
    - `users_table`, string. Database table for SFTP users
    - `manage_users`, integer. Set to 0 to disable users management, 1 to enable
    - `track_quota`, integer. Set the preferred mode to track users quota between the following choices:
        - 0, disable quota tracking. REST API to scan user dir and update quota will do nothing
        - 1, quota is updated each time a user upload or delete a file even if the user has no quota restrictions
        - 2, quota is updated each time a user upload or delete a file but only for users with quota restrictions. With this configuration the "quota scan" REST API can still be used to periodically update space usage for users without quota restrictions
    - `pool_size`, integer. Sets the maximum number of open connections for `mysql` and `postgresql` driver. Default 0 (unlimited)
    - `users_base_dir`, string. Users default base directory. If no home dir is defined while adding a new user, and this value is a valid absolute path, then the user home dir will be automatically defined as the path obtained joining the base dir and the username
    - `actions`, struct. It contains the command to execute and/or the HTTP URL to notify and the trigger conditions. See the "Custom Actions" paragraph for more details
        - `execute_on`, list of strings. Valid values are `add`, `update`, `delete`. `update` action will not be fired for internal updates such as the last login or the user quota fields.
        - `command`, string. Absolute path to the command to execute. Leave empty to disable.
        - `http_notification_url`, a valid URL. Leave empty to disable.
    - `external_auth_program`, string. Absolute path to an external program to use for users authentication. See the "External Authentication" paragraph for more details. Leave empty to disable.
    - `external_auth_scope`, integer. 0 means all supported authetication scopes (passwords, public keys and keyboard interactive). 1 means passwords only. 2 means public keys only. 4 means key keyboard interactive only. The flags can be combined, for example 6 means public keys and keyboard interactive
    - `credentials_path`, string. It defines the directory for storing user provided credential files such as Google Cloud Storage credentials. This can be an absolute path or a path relative to the config dir
    - `pre_login_program`, string. Absolute path to an external program to use to modify user details just before the login. See the "Dynamic user modification" paragraph for more details. Leave empty to disable.
- **"httpd"**, the configuration for the HTTP server used to serve REST API
    - `bind_port`, integer. The port used for serving HTTP requests. Set to 0 to disable HTTP server. Default: 8080
    - `bind_address`, string. Leave blank to listen on all available network interfaces. Default: "127.0.0.1"
    - `templates_path`, string. Path to the HTML web templates. This can be an absolute path or a path relative to the config dir
    - `static_files_path`, string. Path to the static files for the web interface. This can be an absolute path or a path relative to the config dir
    - `backups_path`, string. Path to the backup directory. This can be an absolute path or a path relative to the config dir. We don't allow backups in arbitrary paths for security reasons
    - `auth_user_file`, string. Path to a file used to store usernames and password for basic authentication. This can be an absolute path or a path relative to the config dir. We support HTTP basic authentication and the file format must conform to the one generated using the Apache `htpasswd` tool. The supported password formats are bcrypt (`$2y$` prefix) and md5 crypt (`$apr1$` prefix). If empty HTTP authentication is disabled.
    - `certificate_file`, string. Certificate for HTTPS. This can be an absolute path or a path relative to the config dir.
    - `certificate_key_file`, string. Private key matching the above certificate. This can be an absolute path or a path relative to the config dir. If both the certificate and the private key are provided the server will expect HTTPS connections. Certificate and key files can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows.

Here is a full example showing the default config in JSON format:

```json
{
  "sftpd": {
    "bind_port": 2022,
    "bind_address": "",
    "idle_timeout": 15,
    "max_auth_tries": 0,
    "umask": "0022",
    "banner": "",
    "upload_mode": 0,
    "actions": {
      "execute_on": [],
      "command": "",
      "http_notification_url": ""
    },
    "keys": [],
    "enable_scp": false,
    "kex_algorithms": [],
    "ciphers": [],
    "macs": [],
    "login_banner_file": "",
    "setstat_mode": 0,
    "enabled_ssh_commands": ["md5sum", "sha1sum", "cd", "pwd"],
    "keyboard_interactive_auth_program": "",
    "proxy_protocol": 0,
    "proxy_allowed": []
  },
  "data_provider": {
    "driver": "sqlite",
    "name": "sftpgo.db",
    "host": "",
    "port": 5432,
    "username": "",
    "password": "",
    "sslmode": 0,
    "connection_string": "",
    "users_table": "users",
    "manage_users": 1,
    "track_quota": 2,
    "pool_size": 0,
    "users_base_dir": "",
    "actions": {
      "execute_on": [],
      "command": "",
      "http_notification_url": ""
    },
    "external_auth_program": "",
    "external_auth_scope": 0,
    "credentials_path": "credentials",
    "pre_login_program": ""
  },
  "httpd": {
    "bind_port": 8080,
    "bind_address": "127.0.0.1",
    "templates_path": "templates",
    "static_files_path": "static",
    "backups_path": "backups",
    "auth_user_file": "",
    "certificate_file": "",
    "certificate_key_file": ""
  }
}
```

If you want to use a private key that use an algorithm different from RSA or ECDSA or more private keys then generate your own keys and replace the empty `keys` array with something like this:

```json
"keys": [
  {
    "private_key": "id_rsa"
  },
  {
    "private_key": "id_ecdsa"
  },
  {
    "private_key": "id_ed25519"
  }
]
```

where `id_rsa`, `id_ecdsa` and `id_ed25519` are your generated keys. You can use absolute paths or paths relative to the configuration directory.

The configuration can be read from JSON, TOML, YAML, HCL, envfile and Java properties config files, if your `config-file` flag is set to `sftpgo` (default value) you need to create a configuration file called `sftpgo.json` or `sftpgo.yaml` and so on inside `config-dir`.

You can also override all the available configuration options using environment variables, sftpgo will check for environment variables with a name matching the key uppercased and prefixed with the `SFTPGO_`. You need to use `__` to traverse a struct.

Let's see some examples:

- To set sftpd `bind_port` you need to define the env var `SFTPGO_SFTPD__BIND_PORT`
- To set the `execute_on` actions you need to define the env var `SFTPGO_SFTPD__ACTIONS__EXECUTE_ON` for example `SFTPGO_SFTPD__ACTIONS__EXECUTE_ON=upload,download`

Please note that to override configuration options with environment variables a configuration file containing the options to override is required. You can, for example, deploy the default configuration file and then override the options you need to customize using environment variables.

### Data provider initialization

Before starting `sftpgo serve` please ensure that the configured dataprovider is properly initialized.

SQL based data providers (SQLite, MySQL, PostgreSQL) requires the creation of a database containing the required tables. Memory and bolt data providers does not require an initialization.

After configuring the data provider, using the configuration file, you can create the required database structure using the `initprovider` command.
For SQLite provider, the `initprovider` command will auto create the database file, if missing, and the required tables.
For PostgreSQL and MySQL providers you need to create the configured database, the `initprovider` command will create the required tables.

For example you can simply execute the following command from the configuration directory:

```
sftpgo initprovider
```

Take a look at the CLI usage to learn how to specify a different configuration file:

```
sftpgo initprovider --help
```

The `initprovider` command is enough for new installations. From now on, the database structure will be automatically checked and updated, if required, at startup.

If you are upgrading from version 0.9.5 or before you have to manually execute the SQL scripts to create the required database structure. These script can be found inside the source tree [sql](./sql "sql") directory. The SQL scripts filename is, by convention, the date as `YYYYMMDD` and the suffix `.sql`. You need to apply all the SQL scripts for your database ordered by name, for example `20190828.sql` must be applied before `20191112.sql` and so on.
Example for SQLite: `find sql/sqlite/ -type f -iname '*.sql' -print | sort -n | xargs cat | sqlite3 sftpgo.db`.
After applying these scripts your database structure is the same as the one obtained using `initprovider` for new installations, so from now on you don't have to manually upgrade your database anymore.

The `memory` provider can load users from a dump obtained using the `dumpdata` REST API. The path to this dump file can be configured using the dataprovider `name` configuration key. It will be loaded at startup and can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows. The `memory` provider will not modify the provided file so quota usage and last login will not be persisted.

### Starting SFTGo in server mode

To start the SFTP Server with the default values for the command line flags simply use:

```
sftpgo serve
```

On Windows you can register `SFTPGo` as Windows Service, take a look at the CLI usage to learn how:

```
sftpgo.exe service --help
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

`install` command accepts the same flags valid for `serve`.

After installing as Windows Service please remember to allow network access to the SFTPGo executable using something like this:

```
netsh advfirewall firewall add rule name="SFTPGo Service" dir=in action=allow program="C:\Program Files\SFTPGo\sftpgo.exe"
```

or through the Windows Firewall GUI.

## External Authentication

Custom authentication methods can easily be added. SFTPGo supports external authentication modules, and writing a new backend can be as simple as a few lines of shell script.

To enable external authentication you must set the absolute path of your authentication program using `external_auth_program` key in your configuration file.

The external program can read the following environment variables to get info about the user trying to authenticate:

- `SFTPGO_AUTHD_USERNAME`
- `SFTPGO_AUTHD_PASSWORD`, not empty for password authentication
- `SFTPGO_AUTHD_PUBLIC_KEY`, not empty for public key authentication
- `SFTPGO_AUTHD_KEYBOARD_INTERACTIVE`, not empty for keyboard interactive authentication

Previous global environment variables aren't cleared when the script is called. The content of these variables is _not_ quoted. They may contain special characters. They are under the control of a possibly malicious remote user.
The program must write, on its standard output, a valid SFTPGo user serialized as JSON if the authentication succeed or an user with an empty username if the authentication fails.
If the authentication succeed the user will be automatically added/updated inside the defined data provider. Actions defined for users added/updated will not be executed in this case.
The external program should check authentication only, if there are login restrictions such as user disabled, expired, login allowed only from specific IP addresses it is enough to populate the matching user fields and these conditions will be checked in the same way as for built-in users.
The external auth program should finish very quickly, anyway it will be killed if it does not exit within 60 seconds.
This method is slower than built-in authentication, but it's very flexible as anyone can easily write his own authentication program.
You can also restrict the authentication scope for the external program using the `external_auth_scope` configuration key:

- 0 means all supported authetication scopes, the external program will be used for password, public key and keyboard interactive authentication
- 1 means passwords only
- 2 means public keys only
- 4 means keyboard interactive only

You can combine the scopes, for example 3 means password and public key, 5 password and keyboard interactive and so on.

Let's see a very basic example. Our sample authentication program will only accept user `test_user` with any password or public key.

```
#!/bin/sh

if test "$SFTPGO_AUTHD_USERNAME" = "test_user"; then
  echo '{"status":1,"username":"test_user","expiration_date":0,"home_dir":"/tmp/test_user","uid":0,"gid":0,"max_sessions":0,"quota_size":0,"quota_files":100000,"permissions":{"/":["*"],"/somedir":["list","download"]},"upload_bandwidth":0,"download_bandwidth":0,"filters":{"allowed_ip":[],"denied_ip":[]},"public_keys":[]}'
else
  echo '{"username":""}'
fi
```

If you have an external authentication program that could be useful for others too, please let us know and/or send a pull request.

## Dynamic user modification

Dynamic user modification is supported via an external program that can be executed just before the user login.
To enable dynamic user modification you must set the absolute path of your program using the `pre_login_program` key in your configuration file.

The external program can read the following environment variables to get info about the user trying to login:

- `SFTPGO_LOGIND_USER`, it contains the user trying to login serialized as JSON
- `SFTPGO_LOGIND_METHOD`, possible values are: `password`, `publickey` and `keyboard-interactive`

The program must write, on its the standard output, an empty string (or no response at all) if no user update is needed or the updated SFTPGo user serialized as JSON. Actions defined for users update will not be executed in this case.
The JSON response can include only the fields that need to the updated instead of the full user, for example if you want to disable the user you can return a response like this:

```json
{"status": 0}
```
The external program must finish within 60 seconds.

If an error happens while executing your program then login will be denied. "Dynamic user modification" and "External Authentication" are mutally exclusive.

Let's see a very basic example. Our sample program will grant access to the user `test_user` only in the time range 10:00-18:00. Other users will not be modified since the program will terminate with no output.

```
#!/bin/bash

CURRENT_TIME=`date +%H:%M`
if [[ "$SFTPGO_LOGIND_USER" =~ "\"test_user\"" ]]
then
  if [[ $CURRENT_TIME > "18:00" || $CURRENT_TIME < "10:00" ]]
  then
    echo '{"status":0}'
  else
    echo '{"status":1}'
  fi
fi
```

Please note that this is a demo program and it could not work in all cases, for example the username should be obtained parsing the JSON serialized user and not searching the username inside the JSON as showed here.

## Keyboard Interactive Authentication

Keyboard interactive authentication is, in general case, a series of question asked by the server with responses provided by the client.
This authentication method is typically used for multi factor authentication.
There is no restrictions on the number of questions asked on a particular authentication stage; there is also no restrictions on the number of stages involving different sets of questions.

To enable keyboard interactive authentication you must set the absolute path of your authentication program using `keyboard_interactive_auth_program` key in your configuration file.

The external program can read the following environment variables to get info about the user trying to authenticate:

- `SFTPGO_AUTHD_USERNAME`
- `SFTPGO_AUTHD_PASSWORD`, this is the hashed password as stored inside the data provider

Previous global environment variables aren't cleared when the script is called. The content of these variables is _not_ quoted. They may contain special characters.

The program must write the questions on its standard output, in a single line, using the following struct JSON serialized:

- `instruction`, string. A short description to show to the user that is trying to authenticate. Can be empty or omitted
- `questions`, list of questions to be asked to the user
- `echos` list of boolean flags corresponding to the questions (so the lengths of both lists must be the same) and indicating whether user's reply for a particular question should be echoed on the screen while they are typing: true if it should be echoed, or false if it should be hidden.
- `check_password` optional integer. Ask exactly one question and set this field to 1 if the expected answer is the user password and you want that SFTPGo checks it for you. If the password is correct the returned response to the program is `OK`. If the password is wrong the program will be terminated and an authentication error will be returned to the user that is trying to authenticate
- `auth_result`, integer. Set this field to 1 to indicate successful authentication, 0 is ignored, any other value means authentication error. If this fields is found and it is different from 0 then SFTPGo does not read any other questions from the external program and finalize the authentication.

SFTPGo writes the user answers to the program standard input, one per line, in the same order of the questions.
Please be sure that your program receive the answers for all the issued questions before asking for the next ones.

Keyboard interactive authentication can be chained to the external authentication.
The authentication must finish within 60 seconds.

Let's see a very basic example. Our sample keyboard interactive authentication program will ask for 2 sets of questions and accept the user if the answer to the last question is `answer3`.

```
#!/bin/sh

echo '{"questions":["Question1: ","Question2: "],"instruction":"This is a sample for keyboard interactive authentication","echos":[true,false]}'

read ANSWER1
read ANSWER2

echo '{"questions":["Question3: "],"instruction":"","echos":[true]}'

read ANSWER3

if test "$ANSWER3" = "answer3"; then
	echo '{"auth_result":1}'
else
	echo '{"auth_result":-1}'
fi
```

and here is an example where SFTPGo checks the user password for you:

```
#!/bin/sh

echo '{"questions":["Password: "],"instruction":"This is a sample for keyboard interactive authentication","echos":[false],"check_password":1}'

read ANSWER1

if test "$ANSWER1" != "OK"; then
  exit 1
fi

echo '{"questions":["One time token: "],"instruction":"","echos":[false]}'

read ANSWER2

if test "$ANSWER2" = "token"; then
	echo '{"auth_result":1}'
else
	echo '{"auth_result":-1}'
fi
```

## Custom Actions

SFTPGo allows to configure custom commands and/or HTTP notifications on file upload, download, delete, rename, on SSH commands and on user add, update and delete.

The `actions` struct inside the "sftpd" configuration section allows to configure the actions for file operations and SSH commands.

Actions will not be executed if an error is detected and so a partial file is uploaded or an SSH command is not successfully completed. The `upload` condition includes both uploads to new files and overwrite of existing files. The `ssh_cmd` condition will be triggered after a command is successfully executed via SSH. `scp` will trigger the `download` and `upload` conditions and not `ssh_cmd`.

The `command`, if defined, is invoked with the following arguments:

- `action`, string, possible values are: `download`, `upload`, `delete`, `rename`, `ssh_cmd`
- `username`
- `path` is the full filesystem path, can be empty for some ssh commands
- `target_path`, non empty for `rename` action
- `ssh_cmd`, non empty for `ssh_cmd` action

The `command` can also read the following environment variables:

- `SFTPGO_ACTION`
- `SFTPGO_ACTION_USERNAME`
- `SFTPGO_ACTION_PATH`
- `SFTPGO_ACTION_TARGET`, non empty for `rename` `SFTPGO_ACTION`
- `SFTPGO_ACTION_SSH_CMD`, non empty for `ssh_cmd` `SFTPGO_ACTION`
- `SFTPGO_ACTION_FILE_SIZE`, non empty for `upload`, `download` and `delete` `SFTPGO_ACTION`
- `SFTPGO_ACTION_LOCAL_FILE`, `true` if the affected file is stored on the local filesystem, otherwise `false`

Previous global environment variables aren't cleared when the script is called.
The `command` must finish within 30 seconds.

The `http_notification_url`, if defined, will contain the following, percent encoded, query string parameters:

- `action`
- `username`
- `path`
- `local_file`, `true` if the affected file is stored on the local filesystem, otherwise `false`
- `target_path`, added for `rename` action
- `ssh_cmd`, added for `ssh_cmd` action
- `file_size`, added for `upload`, `download`, `delete` actions

The HTTP request is executed with a 15 seconds timeout.

The `actions` struct inside the "data_provider" configuration section allows to configure actions on user add, update, delete.

Actions will not be fired for internal updates such as the last login or the user quota fields or after external authentication.

The `command`, if defined, is invoked with the following arguments:

- `action`, string, possible values are: `add`, `update`, `delete`
- `username`
- `ID`
- `status`
- `expiration_date`
- `home_dir`
- `uid`
- `gid`

The `command` can also read the following environment variables:

- `SFTPGO_USER_ACTION`
- `SFTPGO_USER_USERNAME`
- `SFTPGO_USER_PASSWORD`, hashed password as stored inside the data provider, can be empty if the user does not login using a password
- `SFTPGO_USER_ID`
- `SFTPGO_USER_STATUS`
- `SFTPGO_USER_EXPIRATION_DATE`
- `SFTPGO_USER_HOME_DIR`
- `SFTPGO_USER_UID`
- `SFTPGO_USER_GID`
- `SFTPGO_USER_QUOTA_FILES`
- `SFTPGO_USER_QUOTA_SIZE`
- `SFTPGO_USER_UPLOAD_BANDWIDTH`
- `SFTPGO_USER_DOWNLOAD_BANDWIDTH`
- `SFTPGO_USER_MAX_SESSIONS`
- `SFTPGO_USER_FS_PROVIDER`

Previous global environment variables aren't cleared when the script is called.
The `command` must finish within 15 seconds.

The `http_notification_url`, if defined, will be called invoked as http POST. The action is added to the query string, for example `<http_notification_url>?action=update` and the user is sent serialized as JSON inside the POST body with sensitive fields removed.

The HTTP request is executed with a 15 seconds timeout.

## S3 Compabible Object Storage backends

Each user can be mapped to whole bucket or to a bucket virtual folder, this way the mapped bucket/virtual folder is exposed over SFTP/SCP.

Specifying a different `key_prefix` you can assign different virtual folders of the same bucket to different users. This is similar to a chroot directory for local filesystem. Each SFTP/SCP user can only access to the assigned virtual folder and to its contents The virtual folder identified by `key_prefix` does not need to be pre-created.

SFTPGo uses multipart uploads and parallel downloads for storing and retrieving files from S3.

The configured bucket must exist.

To connect SFTPGo to AWS you need to specify credentials, and a `region` is required too, here is the list of available [AWS regions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions). For example if your bucket is at `Frankfurt` you have to set the region to `eu-central-1`. You can specify an AWS [storage class](https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html) too, leave blank to use the default AWS storage class. An endpoint is required if you are connecting to a Compatible AWS Storage such as [MinIO](https://min.io/).

AWS SDK has different options for credentials. [More Detail](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html). We support:
1. Providing [Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys).
2. Use IAM roles for Amazon EC2
3. Use IAM roles for tasks if your application uses an ECS task definition

So you need to provide access keys to activate option 1 or leave them blank to use the other ways to specify credentials.

Some SFTP commands doesn't work over S3:

- `symlink` and `chtimes` will fail
- `chown` and `chmod` are silently ignored
- upload resume is not supported
- upload mode `atomic` is ignored since S3 uploads are already atomic

Other notes:

- `rename` is a two steps operation: server-side copy and then deletion. So it is not atomic as for local filesystem.
- We don't support renaming non empty directories since we should rename all the contents too and this could take long time: think about directories with thousands of files, for each file we should do an AWS API call.
- For server side encryption you have to configure the mapped bucket to automatically encrypt objects.
- A local home directory is still required to store temporary files.

## Google Cloud Storage backend

Each user can be mapped with a Google Cloud Storage bucket or a bucket virtual folder, this way the mapped bucket/virtual folder is exposed over SFTP/SCP. This backend is very similar to the S3 backend and it has the same limitations.

To connect SFTPGo to Google Cloud Storage you can use use the Application Default Credentials (ADC) strategy to try to find your application's credentials automatically or you can explicitly provide a JSON credentials file that you can obtain from the Google Cloud Console, take a look [here](https://cloud.google.com/docs/authentication/production#providing_credentials_to_your_application) for details.

You can optionally specify a [storage class](https://cloud.google.com/storage/docs/storage-classes) too, leave blank to use the default storage class.

## Other Storage backends

Adding new storage backends it's quite easy:

- implement the [Fs interface](./vfs/vfs.go#L18 "interface for filesystem backends").
- update the user method `GetFilesystem` to return the new backend
- update the web interface and the REST API CLI
- add the flags for the new storage backed to the `portable` mode

Anyway some backends require a pay per use account (or they offer free account for a limited time period only), to be able to add support for such backends or to review pull requests please provide a test account. The test account must be available over the time to be able to maintain the backend and do basic tests before each new release.

## Portable mode

SFTPGo allows to share a single directory on demand using the `portable` subcommand:

```
sftpgo portable --help
To serve the current working directory with auto generated credentials simply use:

sftpgo portable

Please take a look at the usage below to customize the serving parameters

Usage:
  sftpgo portable [flags]

Flags:
  -C, --advertise-credentials           If the SFTP service is advertised via multicast DNS this flag allows to put username/password inside the advertised TXT record
  -S, --advertise-service               Advertise SFTP service using multicast DNS (default true)
  -d, --directory string                Path to the directory to serve. This can be an absolute path or a path relative to the current directory (default ".")
  -f, --fs-provider int                 0 means local filesystem, 1 Amazon S3 compatible, 2 Google Cloud Storage
      --gcs-automatic-credentials int   0 means explicit credentials using a JSON credentials file, 1 automatic (default 1)
      --gcs-bucket string
      --gcs-credentials-file string     Google Cloud Storage JSON credentials file
      --gcs-key-prefix string           Allows to restrict access to the virtual folder identified by this prefix and its contents
      --gcs-storage-class string
  -h, --help                            help for portable
  -l, --log-file-path string            Leave empty to disable logging
  -p, --password string                 Leave empty to use an auto generated value
  -g, --permissions strings             User's permissions. "*" means any permission (default [list,download])
  -k, --public-key strings
      --s3-access-key string
      --s3-access-secret string
      --s3-bucket string
      --s3-endpoint string
      --s3-key-prefix string            Allows to restrict access to the virtual folder identified by this prefix and its contents
      --s3-region string
      --s3-storage-class string
  -s, --sftpd-port int                  0 means a random non privileged port
  -c, --ssh-commands strings            SSH commands to enable. "*" means any supported SSH command including scp (default [md5sum,sha1sum,cd,pwd])
  -u, --username string                 Leave empty to use an auto generated value
```

In portable mode SFTPGo can advertise the SFTP service and, optionally, the credentials via multicast DNS, so there is a standard way to discover the service and to automatically connect to it.

Here is an example of the advertised service including credentials as seen using `avahi-browse`:

```
= enp0s31f6 IPv4 SFTPGo portable 53705                         SFTP File Transfer   local
   hostname = [p1.local]
   address = [192.168.1.230]
   port = [53705]
   txt = ["password=EWOo6pJe" "user=user" "version=0.9.3-dev-b409523-dirty-2019-10-26T13:43:32Z"]
```

## Account's configuration properties

For each account the following properties can be configured:

- `username`
- `password` used for password authentication. For users created using SFTPGo REST API if the password has no known hashing algo prefix it will be stored using argon2id. SFTPGo supports checking passwords stored with bcrypt, pbkdf2, md5crypt and sha512crypt too. For pbkdf2 the supported format is `$<algo>$<iterations>$<salt>$<hashed pwd base64 encoded>`, where algo is `pbkdf2-sha1` or `pbkdf2-sha256` or `pbkdf2-sha512`. For example the `pbkdf2-sha256` of the word `password` using 150000 iterations and `E86a9YMX3zC7` as salt must be stored as `$pbkdf2-sha256$150000$E86a9YMX3zC7$R5J62hsSq+pYw00hLLPKBbcGXmq7fj5+/M0IFoYtZbo=`. For bcrypt the format must be the one supported by golang's [crypto/bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) package, for example the password `secret` with cost `14` must be stored as `$2a$14$ajq8Q7fbtFRQvXpdCq7Jcuy.Rx1h/L4J60Otx.gyNLbAYctGMJ9tK`. For md5crypt and sha512crypt we support the format used in `/etc/shadow` with the `$1$` and `$6$` prefix, this is useful if you are migrating from Unix system user accounts. We support Apache md5crypt (`$apr1$` prefix) too. Using the REST API you can send a password hashed as bcrypt, pbkdf2, md5crypt or sha512crypt and it will be stored as is.
- `public_keys` array of public keys. At least one public key or the password is mandatory.
- `status` 1 means "active", 0 "inactive". An inactive account cannot login.
- `expiration_date` expiration date as unix timestamp in milliseconds. An expired account cannot login. 0 means no expiration.
- `home_dir` the user cannot upload or download files outside this directory. Must be an absolute path.
- `virtual_folders` list of mappings between virtual SFTP/SCP paths and local filesystem paths outside the user home directory. The specified paths must be absolute and the virtual path cannot be "/", it must be a sub directory. The parent directory for the specified virtual path must exist. SFTPGo will try to automatically create any missing parent directory for the configured virtual folders at user login
- `uid`, `gid`. If sftpgo runs as root system user then the created files and directories will be assigned to this system uid/gid. Ignored on windows and if sftpgo runs as non root user: in this case files and directories for all SFTP users will be owned by the system user that runs sftpgo.
- `max_sessions` maximum concurrent sessions. 0 means unlimited.
- `quota_size` maximum size allowed as bytes. 0 means unlimited.
- `quota_files` maximum number of files allowed. 0 means unlimited.
- `permissions` the following per directory permissions are supported:
    - `*` all permissions are granted
    - `list` list items is allowed
    - `download` download files is allowed
    - `upload` upload files is allowed
    - `overwrite` overwrite an existing file, while uploading, is allowed. `upload` permission is required to allow file overwrite
    - `delete` delete files or directories is allowed
    - `rename` rename files or directories is allowed
    - `create_dirs` create directories is allowed
    - `create_symlinks` create symbolic links is allowed
    - `chmod` changing file or directory permissions is allowed. On Windows, only the 0200 bit (owner writable) of mode is used; it controls whether the file's read-only attribute is set or cleared. The other bits are currently unused. Use mode 0400 for a read-only file and 0600 for a readable+writable file.
    - `chown` changing file or directory owner and group is allowed. Changing owner and group is not supported on Windows.
    - `chtimes` changing file or directory access and modification time is allowed
- `upload_bandwidth` maximum upload bandwidth as KB/s, 0 means unlimited.
- `download_bandwidth` maximum download bandwidth as KB/s, 0 means unlimited.
- `allowed_ip`, List of IP/Mask allowed to login. Any IP address not contained in this list cannot login. IP/Mask must be in CIDR notation as defined in RFC 4632 and RFC 4291, for example "192.0.2.0/24" or "2001:db8::/32"
- `denied_ip`, List of IP/Mask not allowed to login. If an IP address is both allowed and denied then login will be denied
- `denied_login_methods`, List of login methods not allowed. The following login methods are supported:
  - `publickey`
  - `password`
  - `keyboard-interactive`
- `file_extensions`, list of struct. These restrictions do not apply to files listing for performance reasons, so a denied file cannot be downloaded/overwritten/renamed but it will still be listed in the list of files. Please note that these restrictions can be easily bypassed. Each struct contains the following fields:
  - `allowed_extensions`, list of, case insensitive, allowed files extension. Shell like expansion is not supported so you have to specify `.jpg` and not `*.jpg`. Any file that does not end with this suffix will be denied
  - `denied_extensions`, list of, case insensitive, denied files extension. Denied file extensions are evaluated before the allowed ones
  - `path`, SFTP/SCP path, if no other specific filter is defined, the filter apply for sub directories too. For example if filters are defined for the paths `/` and `/sub` then the filters for `/` are applied for any file outside the `/sub` directory
- `fs_provider`, filesystem to serve via SFTP. Local filesystem and S3 Compatible Object Storage are supported
- `s3_bucket`, required for S3 filesystem
- `s3_region`, required for S3 filesystem. Must match the region for your bucket. You can find here the list of available [AWS regions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions). For example if your bucket is at `Frankfurt` you have to set the region to `eu-central-1`
- `s3_access_key`
- `s3_access_secret`, if provided it is stored encrypted (AES-256-GCM)
- `s3_endpoint`, specifies a S3 endpoint (server) different from AWS. It is not required if you are connecting to AWS
- `s3_storage_class`, leave blank to use the default or specify a valid AWS [storage class](https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html)
- `s3_key_prefix`, allows to restrict access to the virtual folder identified by this prefix and its contents
- `gcs_bucket`, required for GCS filesystem
- `gcs_credentials`, Google Cloud Storage JSON credentials base64 encoded
- `gcs_automatic_credentials`, integer. Set to 1 to use Application Default Credentials strategy or set to 0 to use explicit credentials via `gcs_credentials`
- `gcs_storage_class`
- `gcs_key_prefix`, allows to restrict access to the virtual folder identified by this prefix and its contents

These properties are stored inside the data provider.

If you want to use your existing accounts you have these options:

- If your accounts are aleady stored inside a supported database, you can create a database view. Since a view is read only, you have to disable user management and quota tracking so SFTPGo will never try to write to the view
- you can import your users inside SFTPGo. Take a look at [sftpgo_api_cli.py](./scripts/README.md "sftpgo api cli script"), it can convert and import users from Linux system users and Pure-FTPd/ProFTPD virtual users
- you can use an external authentication program

## REST API

SFTPGo exposes REST API to manage, backup and restore users and to get real time reports of the active connections with possibility of forcibly closing a connection.

If quota tracking is enabled in `sftpgo` configuration file, then the used size and number of files are updated each time a file is added/removed. If files are added/removed not using SFTP/SCP or if you change `track_quota` from `2` to `1`, you can rescan the users home dir and update the used quota using the REST API.

REST API can be protected using HTTP basic authentication and exposed via HTTPS, if you need more advanced security features you can setup a reverse proxy using an HTTP Server such as Apache or NGNIX.

For example you can keep SFTPGo listening on localhost and expose it externally configuring a reverse proxy using Apache HTTP Server this way:

```
ProxyPass /api/v1 http://127.0.0.1:8080/api/v1
ProxyPassReverse /api/v1 http://127.0.0.1:8080/api/v1
```

and you can add authentication with something like this:

```
<Location /api/v1>
	AuthType Digest
	AuthName "Private"
	AuthDigestDomain "/api/v1"
	AuthDigestProvider file
	AuthUserFile "/etc/httpd/conf/auth_digest"
	Require valid-user
</Location>
```

and, of course, you can configure the web server to use HTTPS.

The OpenAPI 3 schema for the exposed API can be found inside the source tree: [openapi.yaml](./httpd/schema/openapi.yaml "OpenAPI 3 specs").

A sample CLI client for the REST API can be found inside the source tree [scripts](./scripts "scripts") directory.

You can also generate your own REST client, in your preferred programming language or even bash scripts, using an OpenAPI generator such as [swagger-codegen](https://github.com/swagger-api/swagger-codegen) or [OpenAPI Generator](https://openapi-generator.tech/)

## Metrics

SFTPGo exposes [Prometheus](https://prometheus.io/) metrics at the `/metrics` HTTP endpoint.
Several counters and gauges are available, for example:

- Total uploads and downloads
- Total upload and download size
- Total upload and download errors
- Total executed SSH commands
- Total SSH command errors
- Number of active connections
- Data provider availability
- Total successful and failed logins using password, public key or keyboard interactive authentication
- Total HTTP requests served and totals for response code
- Go's runtime details about GC, number of gouroutines and OS threads
- Process information like CPU, memory, file descriptor usage and start time

Please check the `/metrics` page for more details.

## Web Admin

You can easily build your own interface using the exposed REST API, anyway SFTPGo provides also a very basic built-in web interface that allows to manage users and connections.
With the default `httpd` configuration, the web admin is available at the following URL:

[http://127.0.0.1:8080/web](http://127.0.0.1:8080/web)

The web interface can be protected using HTTP basic authentication and exposed via HTTPS, if you need more advanced security features you can setup a reverse proxy as explained for the REST API.

## Logs

Inside the log file each line is a JSON struct, each struct has a `sender` fields that identify the log type.

The logs can be divided into the following categories:

- **"app logs"**, internal logs used to debug `sftpgo`:
    - `sender` string. This is generally the package name that emits the log
    - `time` string. Date/time with millisecond precision
    - `level` string
    - `message` string
- **"transfer logs"**, SFTP/SCP transfer logs:
    - `sender` string. `Upload` or `Download`
    - `time` string. Date/time with millisecond precision
    - `level` string
    - `elapsed_ms`, int64. Elapsed time, as milliseconds, for the upload/download
    - `size_bytes`, int64. Size, as bytes, of the download/upload
    - `username`, string
    - `file_path` string
    - `connection_id` string. Unique connection identifier
    - `protocol` string. `SFTP` or `SCP`
- **"command logs"**, SFTP/SCP command logs:
    - `sender` string. `Rename`, `Rmdir`, `Mkdir`, `Symlink`, `Remove`, `Chmod`, `Chown`, `Chtimes`, `SSHCommand`
    - `level` string
    - `username`, string
    - `file_path` string
    - `target_path` string
    - `filemode` string. Valid for sender `Chmod` otherwise empty
    - `uid` integer. Valid for sender `Chown` otherwise -1
    - `gid` integer. Valid for sender `Chown` otherwise -1
    - `access_time` datetime as YYYY-MM-DDTHH:MM:SS. Valid for sender `Chtimes` otherwise empty
    - `modification_time` datetime as YYYY-MM-DDTHH:MM:SS. Valid for sender `Chtimes` otherwise empty
    - `ssh_command`, string. Valid for sender `SSHCommand` otherwise empty
    - `connection_id` string. Unique connection identifier
    - `protocol` string. `SFTP`, `SCP` or `SSH`
- **"http logs"**, REST API logs:
    - `sender` string. `httpd`
    - `level` string
    - `remote_addr` string. IP and port of the remote client
    - `proto` string, for example `HTTP/1.1`
    - `method` string. HTTP method (`GET`, `POST`, `PUT`, `DELETE` etc.)
    - `user_agent` string
    - `uri` string. Full uri
    - `resp_status` integer. HTTP response status code
    - `resp_size` integer. Size in bytes of the HTTP response
    - `elapsed_ms` int64. Elapsed time, as milliseconds, to complete the request
    - `request_id` string. Unique request identifier
- **"connection failed logs"**, logs for failed attempts to initialize a connection. A connection can fail for an authentication error or other errors such as a client abort or a timeout if the login does not happen in two minutes
    - `sender` string. `connection_failed`
    - `level` string
    - `username`, string. Can be empty if the connection is closed before an authentication attempt
    - `client_ip` string.
    - `login_type` string. Can be `publickey`, `password`, `keyboard-interactive` or `no_auth_tryed`
    - `error` string. Optional error description

## Brute force protection

The **connection failed logs** can be used for integration in tools such as [Fail2ban](http://www.fail2ban.org/). Example of [jails](./fail2ban/jails) and [filters](./fail2ban/filters) working with `systemd`/`journald` are available in fail2ban directory.

## Performance

SFTPGo can easily saturate a Gigabit connection, on low end hardware, with no special configurations and this is generally enough for most use cases.

The main bootlenecks are the encryption and the messages authentication, so if you can use a fast cipher with implicit message authentication, for example `aes128-gcm@openssh.com`, you will get a big performance boost.

There is an open [issue](https://github.com/drakkan/sftpgo/issues/69) with some other suggestions to improve performance and some comparisons against OpenSSH.


## Acknowledgements

- [pkg/sftp](https://github.com/pkg/sftp)
- [go-chi](https://github.com/go-chi/chi)
- [zerolog](https://github.com/rs/zerolog)
- [lumberjack](https://gopkg.in/natefinch/lumberjack.v2)
- [argon2id](https://github.com/alexedwards/argon2id)
- [go-sqlite3](https://github.com/mattn/go-sqlite3)
- [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql)
- [bbolt](https://github.com/etcd-io/bbolt)
- [lib/pq](https://github.com/lib/pq)
- [viper](https://github.com/spf13/viper)
- [cobra](https://github.com/spf13/cobra)
- [xid](https://github.com/rs/xid)
- [nathanaelle/password](https://github.com/nathanaelle/password)
- [PipeAt](https://github.com/eikenb/pipeat)
- [ZeroConf](https://github.com/grandcat/zeroconf)
- [SB Admin 2](https://github.com/BlackrockDigital/startbootstrap-sb-admin-2)
- [shlex](https://github.com/google/shlex)
- [go-proxyproto](https://github.com/pires/go-proxyproto)

Some code was initially taken from [Pterodactyl sftp server](https://github.com/pterodactyl/sftp-server)

## License

GNU GPLv3
