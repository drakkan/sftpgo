# SFTPGo
[![Build Status](https://travis-ci.org/drakkan/sftpgo.svg?branch=master)](https://travis-ci.org/drakkan/sftpgo) [![Code Coverage](https://codecov.io/gh/drakkan/sftpgo/branch/master/graph/badge.svg)](https://codecov.io/gh/drakkan/sftpgo/branch/master) [![Go Report Card](https://goreportcard.com/badge/github.com/drakkan/sftpgo)](https://goreportcard.com/report/github.com/drakkan/sftpgo) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0) [![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

Full featured and highly configurable SFTP server

## Features

- Each account is chrooted to his Home Dir.
- SFTP accounts are virtual accounts stored in a "data provider".
- SQLite, MySQL, PostgreSQL, bbolt (key/value store in pure Go) and in memory data providers are supported.
- Public key and password authentication. Multiple public keys per user are supported.
- Custom authentication using external programs is supported.
- Quota support: accounts can have individual quota expressed as max total size and/or max number of files.
- Bandwidth throttling is supported, with distinct settings for upload and download.
- Per user maximum concurrent sessions.
- Per user and per directory permissions: list directories content, upload, overwrite, download, delete, rename, create directories, create symlinks, changing owner/group and mode, changing access and modification times can be enabled or disabled.
- Per user files/folders ownership: you can map all the users to the system account that runs SFTPGo (all platforms are supported) or you can run SFTPGo as root user and map each user or group of users to a different system account (*NIX only).
- Per user IP filters are supported: login can be restricted to specific ranges of IP addresses or to a specific IP address.
- Configurable custom commands and/or HTTP notifications on file upload, download, delete, rename, on SSH commands and on user add, update and delete.
- Automatically terminating idle connections.
- Atomic uploads are configurable.
- Support for Git repositories over SSH.
- SCP and rsync are supported.
- Support for serving S3 Compatible Object Storage over SFTP.
- Prometheus metrics are exposed.
- REST API for users management, backup, restore and real time reports of the active connections with possibility of forcibly closing a connection.
- Web based interface to easily manage users and connections.
- Easy migration from Linux system user accounts.
- Portable mode: a convenient way to share a single directory on demand.
- Configuration is a your choice: JSON, TOML, YAML, HCL, envfile are supported.
- Log files are accurate and they are saved in the easily parsable JSON format.

## Platforms

SFTPGo is developed and tested on Linux. After each commit the code is automatically built and tested on Linux and macOS using Travis CI.
Regularly the test cases are manually executed and pass on Windows. Other UNIX variants such as *BSD should work too.

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

SFTPGo depends on [go-sqlite3](https://github.com/mattn/go-sqlite3) that is a CGO package and so it requires a `C` compiler at build time.
On Linux and macOS a compiler is easy to install or already installed, on Windows you need to download [MinGW-w64](https://sourceforge.net/projects/mingw-w64/files/) and build SFTPGo from its command prompt.

The compiler is a build time only dependency, it is not not required at runtime.

If you don't need SQLite, you can also get/build SFTPGo setting the environment variable `GCO_ENABLED` to 0, this way SQLite support will be disabled but PostgreSQL, MySQL, bbolt and memory data providers will work and you don't need a `C` compiler for building.

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
  help        Help about any command
  portable    Serve a single directory
  serve       Start the SFTP Server

Flags:
  -h, --help      help for sftpgo
  -v, --version

 Use "sftpgo [command] --help" for more information about a command
```

The `serve` subcommand supports the following flags:

- `--config-dir` string. Location of the config dir. This directory should contain the `sftpgo` configuration file and is used as the base for files with a relative path (eg. the private keys for the SFTP server, the SQLite or bblot database if you use SQLite or bbolt as data provider). The default value is "." or the value of `SFTPGO_CONFIG_DIR` environment variable.
- `--config-file` string. Name of the configuration file. It must be the name of a file stored in config-dir not the absolute path to the configuration file. The specified file name must have no extension we automatically load JSON, YAML, TOML, HCL and Java properties. The default value is "sftpgo" (and therefore `sftpgo.json`, `sftpgo.yaml` and so on are searched) or the value of `SFTPGO_CONFIG_FILE` environment variable.
- `--log-compress` boolean. Determine if the rotated log files should be compressed using gzip. Default `false` or the value of `SFTPGO_LOG_COMPRESS` environment variable (1 or `true`, 0 or `false`). It is unused if `log-file-path` is empty.
- `--log-file-path` string. Location for the log file, default "sftpgo.log" or the value of `SFTPGO_LOG_FILE_PATH` environment variable. Leave empty to write logs to the standard error.
- `--log-max-age` int. Maximum number of days to retain old log files. Default 28 or the value of `SFTPGO_LOG_MAX_AGE` environment variable. It is unused if `log-file-path` is empty.
- `--log-max-backups` int. Maximum number of old log files to retain. Default 5 or the value of `SFTPGO_LOG_MAX_BACKUPS` environment variable. It is unused if `log-file-path` is empty.
- `--log-max-size` int. Maximum size in megabytes of the log file before it gets rotated. Default 10 or the value of `SFTPGO_LOG_MAX_SIZE` environment variable. It is unused if `log-file-path` is empty.
- `--log-verbose` boolean. Enable verbose logs. Default `true` or the value of `SFTPGO_LOG_VERBOSE` environment variable (1 or `true`, 0 or `false`).

If you don't configure any private host keys, the daemon will use `id_rsa` in the configuration directory. If that file doesn't exist, the daemon will attempt to autogenerate it (if the user that executes SFTPGo has write access to the config-dir). The server supports any private key format supported by [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/keys.go#L32).

Before starting `sftpgo` a dataprovider must be configured.

SQL scripts to create the required database structure can be found inside the source tree [sql](./sql "sql") directory. The SQL scripts filename is, by convention, the date as `YYYYMMDD` and the suffix `.sql`. You need to apply all the SQL scripts for your database ordered by name, for example `20190828.sql` must be applied before `20191112.sql` and so on.

The `sftpgo` configuration file contains the following sections:

- **"sftpd"**, the configuration for the SFTP server
    - `bind_port`, integer. The port used for serving SFTP requests. Default: 2022
    - `bind_address`, string. Leave blank to listen on all available network interfaces. Default: ""
    - `idle_timeout`, integer. Time in minutes after which an idle client will be disconnected. 0 menas disabled. Default: 15
    - `max_auth_tries` integer. Maximum number of authentication attempts permitted per connection. If set to a negative number, the number of attempts are unlimited. If set to zero, the number of attempts are limited to 6.
    - `umask`, string. Umask for the new files and directories. This setting has no effect on Windows. Default: "0022"
    - `banner`, string. Identification string used by the server. Leave empty to use the default banner. Default "SFTPGo_<version>"
    - `upload_mode` integer. 0 means standard, the files are uploaded directly to the requested path. 1 means atomic: files are uploaded to a temporary path and renamed to the requested path when the client ends the upload. Atomic mode avoids problems such as a web server that serves partial files when the files are being uploaded. In atomic mode if there is an upload error the temporary file is deleted and so the requested upload path will not contain a partial file. 2 means atomic with resume support: as atomic but if there is an upload error the temporary file is renamed to the requested path and not deleted, this way a client can reconnect and resume the upload.
    - `actions`, struct. It contains the command to execute and/or the HTTP URL to notify and the trigger conditions. See the "Custom Actions" paragraph for more details
        - `execute_on`, list of strings. Valid values are `download`, `upload`, `delete`, `rename`, `ssh_cmd`. Leave empty to disable actions.
        - `command`, string. Absolute path to the command to execute. Leave empty to disable.
        - `http_notification_url`, a valid URL. An HTTP GET request will be executed to this URL. Leave empty to disable.
    - `keys`, struct array. It contains the daemon's private keys. If empty or missing the daemon will search or try to generate `id_rsa` in the configuration directory.
        - `private_key`, path to the private key file. It can be a path relative to the config dir or an absolute one.
    - `enable_scp`, boolean. Default disabled. Set to `true` to enable the experimental SCP support. This setting is deprecated and will be removed in future versions, please add `scp` to the `enabled_ssh_commands` list to enable it
    - `kex_algorithms`, list of strings. Available KEX (Key Exchange) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L46 "Supported kex algos")
    - `ciphers`, list of strings. Allowed ciphers. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L28 "Supported ciphers")
    - `macs`, list of strings. available MAC (message authentication code) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L84 "Supported MACs")
    - `login_banner_file`, path to the login banner file. The contents of the specified file, if any, are sent to the remote user before authentication is allowed. It can be a path relative to the config dir or an absolute one. Leave empty to send no login banner
    - `setstat_mode`, integer. 0 means "normal mode": requests for changing permissions, owner/group and access/modification times are executed. 1 means "ignore mode": requests for changing permissions, owner/group and access/modification times are silently ignored.
    - `enabled_ssh_commands`, list of enabled SSH commands. These SSH commands are enabled by default: `md5sum`, `sha1sum`, `cd`, `pwd`. `*` enables all supported commands. Some commands are implemented directly inside SFTPGo, while for other commands we use system commands that need to be installed and in your system's `PATH`. For system commands we have no direct control on file creation/deletion and so we cannot support remote filesystems, such as S3, and quota check is suboptimal: if quota is enabled, the number of files is checked at the command begin and not while new files are created. The allowed size is calculated as the difference between the max quota and the used one and it is checked against the bytes transferred via SSH. The command is aborted if it uploads more bytes than the remaining allowed size calculated at the command start. Anyway we see the bytes that the remote command send to the local command via SSH, these bytes contain both protocol commands and files and so the size of the files is different from the size trasferred via SSH: for example a command can send compressed files or a protocol command (few bytes) could delete a big file. To mitigate this issue quotas are recalculated at the command end with a full home directory scan, this could be heavy for big directories. If you need system commands and quotas you could consider to disable quota restrictions and periodically update quota usage yourself using the REST API. We support the following SSH commands:
      - `scp`, SCP is an experimental feature, we have our own SCP implementation since we can't rely on "scp" system command to proper handle quotas and user's home dir restrictions. The SCP protocol is quite simple but there is no official docs about it, so we need more testing and feedbacks before enabling it by default. We may not handle some borderline cases or have sneaky bugs. Please do accurate tests yourself before enabling SCP and let us known if something does not work as expected for your use cases. SCP between two remote hosts is supported using the `-3` scp option.
      - `md5sum`, `sha1sum`, `sha256sum`, `sha384sum`, `sha512sum`. Useful to check message digests for uploaded files. These commands are implemented inside SFTPGo so they work even if the matching system commands are not available, for example on Windows.
      - `cd`, `pwd`. Some SFTP clients does not support the SFTP SSH_FXP_REALPATH packet type and so they use `cd` and `pwd` SSH commands to get the initial directory. Currently `cd` do nothing and `pwd` always returns the `/` path.
      - `git-receive-pack`, `git-upload-pack`, `git-upload-archive`. These commands enable support for Git repositories over SSH, they need to be installed and in your system's `PATH`.
      - `rsync`. The `rsync` command need to be installed and in your system's `PATH`. We cannot avoid that rsync create symlinks so if the user has the permission to create symlinks we add the option `--safe-links` to the received rsync command if it is not already set. This should prevent to create symlinks that point outside the home dir. If the user cannot create symlinks we add the option `--munge-links`, if it is not already set. This should make symlinks unusable (but manually recoverable)
- **"data_provider"**, the configuration for the data provider
    - `driver`, string. Supported drivers are `sqlite`, `mysql`, `postgresql`, `bolt`, `memory`
    - `name`, string. Database name. For driver `sqlite` this can be the database name relative to the config dir or the absolute path to the SQLite database.
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
    - `users_base_dir`, string. Users' default base directory. If no home dir is defined while adding a new user, and this value is a valid absolute path, then the user home dir will be automatically defined as the path obtained joining the base dir and the username
    - `actions`, struct. It contains the command to execute and/or the HTTP URL to notify and the trigger conditions. See the "Custom Actions" paragraph for more details
        - `execute_on`, list of strings. Valid values are `add`, `update`, `delete`. `update` action will not be fired for internal updates such as the last login or the user quota fields.
        - `command`, string. Absolute path to the command to execute. Leave empty to disable.
        - `http_notification_url`, a valid URL. Leave empty to disable.
    - `external_auth_program`, string. Absolute path to an external program to use for users authentication. See the "External Authentication" paragraph for more details.
    - `external_auth_scope`, integer. 0 means all supported authetication scopes (passwords and public keys). 1 means passwords only. 2 means public keys only
- **"httpd"**, the configuration for the HTTP server used to serve REST API
    - `bind_port`, integer. The port used for serving HTTP requests. Set to 0 to disable HTTP server. Default: 8080
    - `bind_address`, string. Leave blank to listen on all available network interfaces. Default: "127.0.0.1"
    - `templates_path`, string. Path to the HTML web templates. This can be an absolute path or a path relative to the config dir
    - `static_files_path`, string. Path to the static files for the web interface. This can be an absolute path or a path relative to the config dir
    - `backups_path`, string. Path to the backup directory. This can be an absolute path or a path relative to the config dir. We don't allow backups in arbitrary paths for security reasons

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
    "enabled_ssh_commands": ["md5sum", "sha1sum", "cd", "pwd"]
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
    "external_auth_scope": 0
  },
  "httpd": {
    "bind_port": 8080,
    "bind_address": "127.0.0.1",
    "templates_path": "templates",
    "static_files_path": "static",
    "backups_path": "backups"
  }
}
```

If you want to use a private key that use an algorithm different from RSA or more than one private key then replace the empty `keys` array with something like this:

```json
"keys": [
  {
    "private_key": "id_rsa"
  },
  {
    "private_key": "id_ecdsa"
  }
]
```

The configuration can be read from JSON, TOML, YAML, HCL, envfile and Java properties config files, if your `config-file` flag is set to `sftpgo` (default value) you need to create a configuration file called `sftpgo.json` or `sftpgo.yaml` and so on inside `config-dir`.

You can also override all the available configuration options using environment variables, sftpgo will check for environment variables with a name matching the key uppercased and prefixed with the `SFTPGO_`. You need to use `__` to traverse a struct.

Let's see some examples:

- To set sftpd `bind_port` you need to define the env var `SFTPGO_SFTPD__BIND_PORT`
- To set the `execute_on` actions you need to define the env var `SFTPGO_SFTPD__ACTIONS__EXECUTE_ON` for example `SFTPGO_SFTPD__ACTIONS__EXECUTE_ON=upload,download`

Please note that to override configuration options with environment variables a configuration file containing the options to override is required. You can, for example, deploy the default configuration file and then override the options you need to customize using environment variables.

To start the SFTP Server with the default values for the command line flags simply use:

```
sftpgo serve
```

On Windows you can register `SFTPGo` as Windows Service, take a look at the CLI usage to learn how:

```
sftpgo.exe service --help
Install, Uninstall, Start, Stop and retrieve status for SFTPGo Windows Service

Usage:
  sftpgo service [command]

Available Commands:
  install     Install SFTPGo as Windows Service
  start       Start SFTPGo Windows Service
  status      Retrieve the status for the SFTPGo Windows Service
  stop        Stop SFTPGo Windows Service
  uninstall   Uninstall SFTPGo Windows Service

Flags:
  -h, --help   help for service

Use "sftpgo service [command] --help" for more information about a command.
```

`install` subcommand accepts the same flags valid for `serve`.

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

Previous global environment variables aren't cleared when the script is called. The content of these variables is _not_ quoted. They may contain special characters. They are under the control of a possibly malicious remote user.
The program must respond on the standard output with a valid SFTPGo user serialized as json if the authentication succeed or an user with an empty username if the authentication fails.
If the authentication succeed the user will be automatically added/updated inside the defined data provider. Actions defined for user added/updated will not be executed in this case.
The external program should check authentication only, if there are login restrictions such as user disabled, expired, login allowed only from specific IP addresses it is enough to populate the matching user fields and these conditions will be checked in the same way as for built-in users.
The external auth program must finish within 15 seconds.
This method is slower than built-in authentication, but it's very flexible as anyone can easily write his own authentication program.
You can also restrict the authentication scope for the external program using the `external_auth_scope` configuration key:

- 0 means all supported authetication scopes, the external program will be used for both password and public key authentication
- 1 means passwords only, the external program will not be used for public key authentication
- 2 means public keys only, the external program will not be used for password authentication

Let's see a very basic example. Our sample authentication program will only accept user `test_user` with any password or public key.

```
#!/bin/sh

if test "$SFTPGO_AUTHD_USERNAME" = "test_user"; then
  echo '{"status":1,"username":"test_user","expiration_date":0,"home_dir":"/tmp/test_user","uid":0,"gid":0,"max_sessions":0,"quota_size":0,"quota_files":100000,"permissions":{"/":["*"],"/somedir":["list","download"]},"upload_bandwidth":0,"download_bandwidth":0,"filters":{"allowed_ip":[],"denied_ip":[]},"public_keys":[]}'
else
  echo '{"username":""}'
fi
```

If you have an external authentication program that could be useful for others too, for example LDAP/Active Directory authentication, please let us know and/or send a pull request.

## Custom Actions

SFTPGo allows to configure custom commands and/or HTTP notifications on file upload, download, delete, rename, on SSH commands and on user add, update and delete.

The `actions` struct inside the "sftpd" configuration section allows to configure actions on file upload, download, delete, rename and on SSH commands.

Actions will not be executed if an error is detected and so a partial file is uploaded or downloaded or an SSH command is not successfully completed. The `upload` condition includes both uploads to new files and overwrite of existing files. The `ssh_cmd` condition will be triggered after a command is successfully executed via SSH. `scp` will trigger the `download` and `upload` conditions and not `ssh_cmd`.

The `command`, if defined, is invoked with the following arguments:

- `action`, string, possibile values are: `download`, `upload`, `delete`, `rename`, `ssh_cmd`
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

Previous global environment variables aren't cleared when the script is called.
The `command` must finish within 30 seconds.

The `http_notification_url`, if defined, will contain the following, percent encoded, query string parameters:

- `action`
- `username`
- `path`
- `target_path`, added for `rename` action
- `ssh_cmd`, added for `ssh_cmd` action
- `file_size`, added for `upload`, `download`, `delete` actions

The HTTP request has a 15 seconds timeout.

The `actions` struct inside the "data_provider" configuration section allows to configure actions on user add, update, delete.

Actions will not be fired for internal updates such as the last login or the user quota fields or after external authentication.

The `command`, if defined, is invoked with the following arguments:

- `action`, string, possibile values are: `add`, `update`, `delete`
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
- `SFTPGO_USER_ID`
- `SFTPGO_USER_STATUS`
- `SFTPGO_USER_EXPIRATION_DATE`
- `SFTPGO_USER_HOME_DIR`
- `SFTPGO_USER_UID`
- `SFTPGO_USER_GID`

Previous global environment variables aren't cleared when the script is called.
The `command` must finish within 15 seconds.

The `http_notification_url`, if defined, will be called invoked as http POST. The action is added to the query string, for example `<http_notification_url>?action=update` and the user is sent serialized as json inside the POST body

The HTTP request has a 15 seconds timeout.

## S3 Compabible Object Storage backends

Each user can be mapped with an S3-Compatible bucket, this way the mapped bucket is exposed over SFTP/SCP.
SFTPGo uses multipart uploads and parallel downloads for storing and retrieving files from S3 and automatically try to create the mapped bucket if it does not exists.

Some SFTP commands doesn't work over S3:

- `symlink` and `chtimes` will fail
- `chown`, `chmod` are silently ignored
- upload resume is not supported
- upload mode `atomic` is ignored since S3 uploads are already atomic

Other notes:

- `rename` is a two steps operation: server-side copy and then deletion. So it is not atomic as for local filesystem
- We don't support renaming non empty directories since we should rename all the contents too and this could take long time: think about directories with thousands of files, for each file we should do an AWS API call.
- For server side encryption you have to configure the mapped bucket to automatically encrypt objects.
- A local home directory is still required to store temporary files.

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
  -C, --advertise-credentials     If the SFTP service is advertised via multicast DNS this flag allows to put username/password inside the advertised TXT record
  -S, --advertise-service         Advertise SFTP service using multicast DNS (default true)
  -d, --directory string          Path to the directory to serve. This can be an absolute path or a path relative to the current directory (default ".")
  -f, --fs-provider int           0 means local filesystem, 1 S3 compatible
  -h, --help                      help for portable
  -l, --log-file-path string      Leave empty to disable logging
  -p, --password string           Leave empty to use an auto generated value
  -g, --permissions strings       User's permissions. "*" means any permission (default [list,download])
  -k, --public-key strings
      --s3-access-key string
      --s3-access-secret string
      --s3-bucket string
      --s3-endpoint string
      --s3-region string
      --s3-storage-class string
  -s, --sftpd-port int            0 means a random non privileged port
  -c, --ssh-commands strings      SSH commands to enable. "*" means any supported SSH command including scp (default [md5sum,sha1sum,cd,pwd])
  -u, --username string           Leave empty to use an auto generated value
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
- `password` used for password authentication. For users created using SFTPGo REST API if the password has no known hashing algo prefix it will be stored using argon2id. SFTPGo supports checking passwords stored with bcrypt, pbkdf2, md5crypt and sha512crypt too. For pbkdf2 the supported format is `$<algo>$<iterations>$<salt>$<hashed pwd base64 encoded>`, where algo is `pbkdf2-sha1` or `pbkdf2-sha256` or `pbkdf2-sha512`. For example the `pbkdf2-sha256` of the word `password` using 150000 iterations and `E86a9YMX3zC7` as salt must be stored as `$pbkdf2-sha256$150000$E86a9YMX3zC7$R5J62hsSq+pYw00hLLPKBbcGXmq7fj5+/M0IFoYtZbo=`. For bcrypt the format must be the one supported by golang's [crypto/bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) package, for example the password `secret` with cost `14` must be stored as `$2a$14$ajq8Q7fbtFRQvXpdCq7Jcuy.Rx1h/L4J60Otx.gyNLbAYctGMJ9tK`. For md5crypt and sha512crypt we support the format used in `/etc/shadow` with the `$1$` and `$6$` prefix, this is useful if you are migrating from Unix system user accounts.  Using the REST API you can send a password hashed as bcrypt, pbkdf2, md5crypt or sha512crypt and it will be stored as is.
- `public_keys` array of public keys. At least one public key or the password is mandatory.
- `status` 1 means "active", 0 "inactive". An inactive account cannot login.
- `expiration_date` expiration date as unix timestamp in milliseconds. An expired account cannot login. 0 means no expiration.
- `home_dir` The user cannot upload or download files outside this directory. Must be an absolute path.
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
- `fs_provider`, filesystem to serve via SFTP. Local filesystem and S3 Compatible Object Storage are supported
- `s3_bucket`, required for S3 filesystem
- `s3_region`, required for S3 filesystem
- `s3_access_key`, required for S3 filesystem
- `s3_access_secret`, required for S3 filesystem. It is stored encrypted (AES-256-GCM)
- `s3_endpoint`, specifies s3 endpoint (server) different from AWS
- `s3_storage_class`

These properties are stored inside the data provider.

If you want to use your existing accounts you have these options:

- If your accounts are aleady stored inside a supported database, you can create a database view. Since a view is read only, you have to disable user management and quota tracking so SFTPGo will never try to write to the view
- you can import your users inside SFTPGo. Take a look at [sftpgo_api_cli.py](./scripts/README.md "sftpgo_api_cli script"), it can convert and import users from Linux system users and Pure-FTPd/ProFTPD virtual users
- you can use an external authentication program

## REST API

SFTPGo exposes REST API to manage, backup and restore users and to get real time reports of the active connections with possibility of forcibly closing a connection.

If quota tracking is enabled in `sftpgo` configuration file, then the used size and number of files are updated each time a file is added/removed. If files are added/removed not using SFTP/SCP or if you change `track_quota` from `2` to `1`, you can rescan the users home dir and update the used quota using the REST API.

REST API is designed to run on localhost or on a trusted network, if you need HTTPS and/or authentication you can setup a reverse proxy using an HTTP Server such as Apache or NGNIX.

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
- Total successful and failed logins using a password or a public key
- Total HTTP requests served and totals for response code
- Go's runtime details about GC, number of gouroutines and OS threads
- Process information like CPU, memory, file descriptor usage and start time

Please check the `/metrics` page for more details.

## Web Admin

You can easily build your own interface using the exposed REST API, anyway SFTPGo provides also a very basic built-in web interface that allows to manage users and connections.
With the default `httpd` configuration, the web admin is available at the following URL:

[http://127.0.0.1:8080/web](http://127.0.0.1:8080/web)

If you need HTTPS and/or authentication you can setup a reverse proxy as explained for the REST API.

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
    - `login_type` string. Can be `public_key`, `password` or `no_auth_tryed`
    - `error` string. Optional error description

### Brute force protection

The **connection failed logs** can be used for integration in tools such as [Fail2ban](http://www.fail2ban.org/). Example of [jails](./fail2ban/jails) and [filters](./fail2ban/filters) working with `systemd`/`journald` are available in fail2ban directory.

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
- [ZeroConf](https://github.com/grandcat/zeroconf)
- [SB Admin 2](https://github.com/BlackrockDigital/startbootstrap-sb-admin-2)

Some code was initially taken from [Pterodactyl sftp server](https://github.com/pterodactyl/sftp-server)

## License

GNU GPLv3
