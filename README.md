# SFTPGo

[![Build Status](https://travis-ci.org/drakkan/sftpgo.svg?branch=master)](https://travis-ci.org/drakkan/sftpgo) [![Code Coverage](https://codecov.io/gh/drakkan/sftpgo/branch/master/graph/badge.svg)](https://codecov.io/gh/drakkan/sftpgo/branch/master) [![Go Report Card](https://goreportcard.com/badge/github.com/drakkan/sftpgo)](https://goreportcard.com/report/github.com/drakkan/sftpgo) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0) [![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

Fully featured and highly configurable SFTP server, written in Go

## Features

- Each account is chrooted to its home directory.
- SFTP accounts are virtual accounts stored in a "data provider".
- SQLite, MySQL, PostgreSQL, bbolt (key/value store in pure Go) and in-memory data providers are supported.
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
- [Portable mode](./docs/portable-mode.md): a convenient way to share a single directory on demand.
- Configuration format is at your choice: JSON, TOML, YAML, HCL, envfile are supported.
- Log files are accurate and they are saved in the easily parsable JSON format.

## Platforms

SFTPGo is developed and tested on Linux. After each commit, the code is automatically built and tested on Linux and macOS using Travis CI.
The test cases are regularly manually executed and passed on Windows. Other UNIX variants such as *BSD should work too.

## Requirements

- Go 1.13 or higher as build only dependency.
- A suitable SQL server or key/value store to use as data provider: PostgreSQL 9.4+ or MySQL 5.6+ or SQLite 3.x or bbolt 1.3.x

## Installation

Binary releases for Linux, macOS, and Windows are available. Please visit the [releases](https://github.com/drakkan/sftpgo/releases "releases") page.

Sample Dockerfiles for [Debian](https://www.debian.org "Debian") and [Alpine](https://alpinelinux.org "Alpine") are available inside the source tree [docker](./docker "docker") directory.

Some Linux distro packages are available:

- For Arch Linux via AUR:
  - [sftpgo](https://aur.archlinux.org/packages/sftpgo/). This package follow stable releases. It requires `git`, `gcc` and `go` to build.
  - [sftpgo-bin](https://aur.archlinux.org/packages/sftpgo-bin/). This package follow stable releases downloading the prebuilt linux binary from GitHub. It does not require `git`, `gcc` and `go` to build.
  - [sftpgo-git](https://aur.archlinux.org/packages/sftpgo-git/). This package build and install the latest git master. It requires `git`, `gcc` and `go` to build.

Alternately, you can install the package to your [$GOPATH](https://github.com/golang/go/wiki/GOPATH "GOPATH") with the [go tool](https://golang.org/cmd/go/ "go command") from shell:

```
$ go get -u github.com/drakkan/sftpgo
```

Make sure [Git](https://git-scm.com/downloads) is installed on your machine and in your system's `PATH`.

SFTPGo depends on [go-sqlite3](https://github.com/mattn/go-sqlite3) which is a CGO package and so it requires a `C` compiler at build time.
On Linux and macOS, a compiler is easy to install or already installed. On Windows, you need to download [MinGW-w64](https://sourceforge.net/projects/mingw-w64/files/) and build SFTPGo from its command prompt.

The compiler is a build time only dependency. It is not required at runtime.

If you don't need SQLite, you can also get/build SFTPGo setting the environment variable `GCO_ENABLED` to 0. This way, SQLite support will be disabled and PostgreSQL, MySQL, bbolt and memory data providers will keep working. In this way, you don't need a `C` compiler for building.

Version info, such as git commit and build date, can be embedded setting the following string variables at build time:

- `github.com/drakkan/sftpgo/utils.commit`
- `github.com/drakkan/sftpgo/utils.date`

For example, you can build using the following command:

```
go build -i -ldflags "-s -w -X github.com/drakkan/sftpgo/utils.commit=`git describe --always --dirty` -X github.com/drakkan/sftpgo/utils.date=`date -u +%FT%TZ`" -o sftpgo
```

and you will get a version that includes git commit and build date like this one:

```
sftpgo -v
SFTPGo version: 0.9.0-dev-90607d4-dirty-2019-08-08T19:28:36Z
```

For Linux, a `systemd` sample [service](./init/sftpgo.service "systemd service") can be found inside the source tree.

For macOS, a `launchd` sample [service](./init/com.github.drakkan.sftpgo.plist "launchd plist") can be found inside the source tree. The `launchd` plist assumes that `sftpgo` has `/usr/local/opt/sftpgo` as base directory.

On Windows, you can run `SFTPGo` as Windows Service. Please read the "Configuration" section below for more details.

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

- `--config-dir` string. Location of the config dir. This directory should contain the `sftpgo` configuration file and is used as the base directory for any files that use a relative path (eg. the private keys for the SFTP server, the SQLite or bblot database if you use SQLite or bbolt as data provider). The default value is "." or the value of `SFTPGO_CONFIG_DIR` environment variable.
- `--config-file` string. Name of the configuration file. It must be the name of a file stored in `config-dir`, not the absolute path to the configuration file. The specified file name must have no extension because we automatically append JSON, YAML, TOML, HCL and Java extensions when we search for the file. The default value is "sftpgo" (and therefore `sftpgo.json`, `sftpgo.yaml` and so on are searched) or the value of `SFTPGO_CONFIG_FILE` environment variable.
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
    - `upload_mode` integer. 0 means standard: the files are uploaded directly to the requested path. 1 means atomic: files are uploaded to a temporary path and renamed to the requested path when the client ends the upload. Atomic mode avoids problems such as a web server that serves partial files when the files are being uploaded. In atomic mode, if there is an upload error, the temporary file is deleted and so the requested upload path will not contain a partial file. 2 means atomic with resume support: same as atomic but if there is an upload error, the temporary file is renamed to the requested path and not deleted. This way, a client can reconnect and resume the upload.
    - `actions`, struct. It contains the command to execute and/or the HTTP URL to notify and the trigger conditions. See the "Custom Actions" paragraph for more details
        - `execute_on`, list of strings. Valid values are `download`, `upload`, `delete`, `rename`, `ssh_cmd`. Leave empty to disable actions.
        - `command`, string. Absolute path to the command to execute. Leave empty to disable.
        - `http_notification_url`, a valid URL. An HTTP GET request will be executed to this URL. Leave empty to disable.
    - `keys`, struct array. It contains the daemon's private keys. If empty or missing, the daemon will search or try to generate `id_rsa` and `id_ecdsa` keys in the configuration directory.
        - `private_key`, path to the private key file. It can be a path relative to the config dir or an absolute one.
    - `enable_scp`, boolean. Default disabled. Set to `true` to enable the experimental SCP support. This setting is deprecated and will be removed in future versions. Please add `scp` to the `enabled_ssh_commands` list to enable it.
    - `kex_algorithms`, list of strings. Available KEX (Key Exchange) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L46 "Supported kex algos")
    - `ciphers`, list of strings. Allowed ciphers. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L28 "Supported ciphers")
    - `macs`, list of strings. available MAC (message authentication code) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L84 "Supported MACs")
    - `login_banner_file`, path to the login banner file. The contents of the specified file, if any, are sent to the remote user before authentication is allowed. It can be a path relative to the config dir or an absolute one. Leave empty to disable login banner.
    - `setstat_mode`, integer. 0 means "normal mode": requests for changing permissions, owner/group and access/modification times are executed. 1 means "ignore mode": requests for changing permissions, owner/group and access/modification times are silently ignored.
    - `enabled_ssh_commands`, list of enabled SSH commands. These SSH commands are enabled by default: `md5sum`, `sha1sum`, `cd`, `pwd`. `*` enables all supported commands. Some commands are implemented directly inside SFTPGo, while for other commands we use system commands that need to be installed and in your system's `PATH`. For system commands we have no direct control on file creation/deletion and so we cannot support remote filesystems, such as S3, and quota check is suboptimal: if quota is enabled, the number of files is checked at the command begin and not while new files are created. The allowed size is calculated as the difference between the max quota and the used one, and it is checked against the bytes transferred via SSH. The command is aborted if it uploads more bytes than the remaining allowed size calculated at the command start. Anyway, we see the bytes that the remote command sends to the local command via SSH. These bytes contain both protocol commands and files, and so the size of the files is different from the size trasferred via SSH: for example, a command can send compressed files, or a protocol command (few bytes) could delete a big file. To mitigate this issue, quotas are recalculated at the command end with a full home directory scan. This could be heavy for big directories. If you need system commands and quotas you could consider disabling quota restrictions and periodically update quota usage yourself using the REST API. We support the following SSH commands:
      - `scp`, SCP is an experimental feature, we have our own SCP implementation since we can't rely on "scp" system command to proper handle quotas and user's home dir restrictions. The SCP protocol is quite simple but there is no official docs about it, so we need more testing and feedback before enabling it by default. We may not handle some borderline cases or sneaky bugs. Please do careful tests yourself before enabling SCP and let us known if something does not work as expected for your use cases. SCP between two remote hosts is supported using the `-3` scp option.
      - `md5sum`, `sha1sum`, `sha256sum`, `sha384sum`, `sha512sum`. Useful to check message digests for uploaded files. These commands are implemented inside SFTPGo so they work even if the matching system commands are not available, for example, on Windows.
      - `cd`, `pwd`. Some SFTP clients do not support the SFTP SSH_FXP_REALPATH packet type, so they use `cd` and `pwd` SSH commands to get the initial directory. Currently `cd` does nothing and `pwd` always returns the `/` path.
      - `git-receive-pack`, `git-upload-pack`, `git-upload-archive`. These commands enable support for Git repositories over SSH. They need to be installed and in your system's `PATH`. Git commands are not allowed inside virtual folders or inside directories with file extensions filters.
      - `rsync`. The `rsync` command needs to be installed and in your system's `PATH`. We cannot avoid that rsync creates symlinks, so if the user has the permission to create symlinks, we add the option `--safe-links` to the received rsync command if it is not already set. This should prevent creating symlinks that point outside the home dir. If the user cannot create symlinks, we add the option `--munge-links` if it is not already set. This should make symlinks unusable (but manually recoverable). The `rsync` command interacts with the filesystem directly and it is not aware of virtual folders and file extensions filters, so it will be automatically disabled for users with these features enabled.
    - `keyboard_interactive_auth_program`, string. Absolute path to an external program to use for keyboard interactive authentication. See the "Keyboard Interactive Authentication" paragraph for more details.
    - `proxy_protocol`, integer. Support for [HAProxy PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt). If you are running SFTPGo behind a proxy server such as HAProxy, AWS ELB or NGNIX, you can enable the proxy protocol. It provides a convenient way to safely transport connection information such as a client's address across multiple layers of NAT or TCP proxies to get the real client IP address instead of the proxy IP. Both protocol version 1 and 2 are supported. If the proxy protocol is enabled in SFTPGo then you have to enable the protocol in your proxy configuration too. For example, for HAProxy, add `send-proxy` or `send-proxy-v2` to each server configuration line. The following modes are supported:
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
    - `connectionstring`, string. Provide a custom database connection string. If not empty, this connection string will be used instead of building one using the previous parameters. Leave empty for drivers `bolt` and `memory`
    - `users_table`, string. Database table for SFTP users
    - `manage_users`, integer. Set to 0 to disable users management, 1 to enable
    - `track_quota`, integer. Set the preferred mode to track users quota between the following choices:
        - 0, disable quota tracking. REST API to scan user dir and update quota will do nothing
        - 1, quota is updated each time a user uploads or deletes a file, even if the user has no quota restrictions
        - 2, quota is updated each time a user uploads or deletes a file, but only for users with quota restrictions. With this configuration, the "quota scan" REST API can still be used to periodically update space usage for users without quota restrictions
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
    - `auth_user_file`, string. Path to a file used to store usernames and passwords for basic authentication. This can be an absolute path or a path relative to the config dir. We support HTTP basic authentication, and the file format must conform to the one generated using the Apache `htpasswd` tool. The supported password formats are bcrypt (`$2y$` prefix) and md5 crypt (`$apr1$` prefix). If empty, HTTP authentication is disabled.
    - `certificate_file`, string. Certificate for HTTPS. This can be an absolute path or a path relative to the config dir.
    - `certificate_key_file`, string. Private key matching the above certificate. This can be an absolute path or a path relative to the config dir. If both the certificate and the private key are provided, the server will expect HTTPS connections. Certificate and key files can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows.

A full example showing the default config (in JSON format) can be found [here](./sftpgo.json).

If you want to use a private key that use an algorithm different from RSA or ECDSA, or more private keys, then generate your own keys and replace the empty `keys` array with something like this:

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

where `id_rsa`, `id_ecdsa` and `id_ed25519` in this example are files containing your generated keys. You can use absolute paths or paths relative to the configuration directory.

The configuration can be read from JSON, TOML, YAML, HCL, envfile and Java properties config files. If your `config-file` flag is set to `sftpgo` (default value), you need to create a configuration file called `sftpgo.json` or `sftpgo.yaml` and so on inside `config-dir`.

You can also override all the available configuration options using environment variables. SFTPGo will check for environment variables with a name matching the key uppercased and prefixed with the `SFTPGO_`. You need to use `__` to traverse a struct.

Let's see some examples:

- To set sftpd `bind_port`, you need to define the env var `SFTPGO_SFTPD__BIND_PORT`
- To set the `execute_on` actions, you need to define the env var `SFTPGO_SFTPD__ACTIONS__EXECUTE_ON`. For example `SFTPGO_SFTPD__ACTIONS__EXECUTE_ON=upload,download`

Please note that, to override configuration options with environment variables, a configuration file containing the options to override is required. You can, for example, deploy the default configuration file and then override the options you need to customize using environment variables.

### Data provider initialization

Before starting `sftpgo serve`, please ensure that the configured dataprovider is properly initialized.

SQL based data providers (SQLite, MySQL, PostgreSQL) require the creation of a database containing the required tables. Memory and bolt data providers do not require an initialization.

After configuring the data provider using the configuration file, you can create the required database structure using the `initprovider` command.
For SQLite provider, the `initprovider` command will auto create the database file, if missing, and the required tables.
For PostgreSQL and MySQL providers, you need to create the configured database, and the `initprovider` command will create the required tables.

For example, you can simply execute the following command from the configuration directory:

```
sftpgo initprovider
```

Take a look at the CLI usage to learn how to specify a different configuration file:

```
sftpgo initprovider --help
```

The `initprovider` command is enough for new installations. From now on, the database structure will be automatically checked and updated, if required, at startup.

If you are upgrading from version 0.9.5 or before, you have to manually execute the SQL scripts to create the required database structure. These scripts can be found inside the source tree [sql](./sql "sql") directory. The SQL scripts filename is, by convention, the date as `YYYYMMDD` and the suffix `.sql`. You need to apply all the SQL scripts for your database ordered by name. For example, `20190828.sql` must be applied before `20191112.sql`, and so on.
Example for SQLite: `find sql/sqlite/ -type f -iname '*.sql' -print | sort -n | xargs cat | sqlite3 sftpgo.db`.
After applying these scripts, your database structure is the same as the one obtained using `initprovider` for new installations, so from now on, you don't have to manually upgrade your database anymore.

The `memory` provider can load users from a dump obtained using the `dumpdata` REST API. The path to this dump file can be configured using the dataprovider `name` configuration key. It will be loaded at startup and can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows. The `memory` provider will not modify the provided file so quota usage and last login will not be persisted.

### Starting SFTGo in server mode

To start the SFTP Server with the default values for the command line flags, simply use:

```
sftpgo serve
```

On Windows, you can register `SFTPGo` as Windows Service. Take a look at the CLI usage to learn how:

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

After installing as a Windows Service, please remember to allow network access to the SFTPGo executable using something like this:

```
netsh advfirewall firewall add rule name="SFTPGo Service" dir=in action=allow program="C:\Program Files\SFTPGo\sftpgo.exe"
```

or through the Windows Firewall GUI.

## Authentication options

### External Authentication

Custom authentication methods can easily be added. SFTPGo supports external authentication modules, and writing a new backend can be as simple as a few lines of shell script. More information can be found [here](./docs/external-auth.md).

### Keyboard Interactive Authentication

Keyboard interactive authentication is, in general, a series of questions asked by the server with responses provided by the client.
This authentication method is typically used for multi-factor authentication.

More information can be found [here](./docs/keyboard-interactive.md).

## Dynamic user modification

The user configuration, retrieved from the data provider, can be modified by an external program. More information about this can be found [here](./docs/dynamic-user-mod.md).

## Custom Actions

SFTPGo allows you to configure custom commands and/or HTTP notifications on file upload, download, delete, rename, on SSH commands and on user add, update and delete.

More information about custom actions can be found [here](./docs/custom-actions.md).

## Storage backends

### S3 Compabible Object Storage backends

Each user can be mapped to whole bucket or to a bucket virtual folder. This way, the mapped bucket/virtual folder is exposed over SFTP/SCP. More information about S3 integration can be found [here](./docs/s3.md).

### Google Cloud Storage backend

Each user can be mapped with a Google Cloud Storage bucket or a bucket virtual folder. This way, the mapped bucket/virtual folder is exposed over SFTP/SCP. This backend is very similar to the S3 backend, and it has the same limitations. More information about S3 integration can be found [here](./docs/google-cloud-storage.md).

### Other Storage backends

Adding new storage backends is quite easy:

- implement the [Fs interface](./vfs/vfs.go#L18 "interface for filesystem backends").
- update the user method `GetFilesystem` to return the new backend
- update the web interface and the REST API CLI
- add the flags for the new storage backed to the `portable` mode

Anyway, some backends require a pay per use account (or they offer free account for a limited time period only). To be able to add support for such backends or to review pull requests, please provide a test account. The test account must be available for enough time to be able to maintain the backend and do basic tests before each new release.

## REST API

SFTPGo exposes REST API to manage, backup, and restore users, and to get real time reports of the active connections with the ability to forcibly close a connection. More information about the REST API can be found [here](./docs/rest-api.md).

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

You can easily build your own interface using the exposed REST API. Anyway, SFTPGo also provides a very basic built-in web interface that allows you to manage users and connections.
With the default `httpd` configuration, the web admin is available at the following URL:

[http://127.0.0.1:8080/web](http://127.0.0.1:8080/web)

The web interface can be protected using HTTP basic authentication and exposed via HTTPS. If you need more advanced security features, you can setup a reverse proxy as explained for the REST API.

## Logs

Inside the log file, each line is a JSON struct. The struct is documented [here](./docs/logs.md).

## Brute force protection

The **connection failed logs** can be used for integration in tools such as [Fail2ban](http://www.fail2ban.org/). Example of [jails](./fail2ban/jails) and [filters](./fail2ban/filters) working with `systemd`/`journald` are available in fail2ban directory.

## Account's configuration properties

Details information about account configuration properties can be found [here](./docs/account.md).

## Performance

SFTPGo can easily saturate a Gigabit connection on low end hardware with no special configuration, and this is generally enough for most use cases.

The main bootlenecks are the encryption and the messages authentication, so if you can use a fast cipher with implicit message authentication, for example `aes128-gcm@openssh.com`, you will get a big performance boost.

More in-depth analysis of performance can be found [here](./docs/performance.md).

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
