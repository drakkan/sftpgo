# SFTPGo
[![Build Status](https://travis-ci.org/drakkan/sftpgo.svg?branch=master)](https://travis-ci.org/drakkan/sftpgo) [![Code Coverage](https://codecov.io/gh/drakkan/sftpgo/branch/master/graph/badge.svg)](https://codecov.io/gh/drakkan/sftpgo/branch/master) [![Go Report Card](https://goreportcard.com/badge/github.com/drakkan/sftpgo)](https://goreportcard.com/report/github.com/drakkan/sftpgo) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0) [![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

Full featured and highly configurable SFTP server

## Features

- Each account is chrooted to his Home Dir.
- SFTP accounts are virtual accounts stored in a "data provider".
- SQLite, MySQL, PostgreSQL and bbolt (key/value store in pure Go) data providers are supported.
- Public key and password authentication. Multiple public keys per user are supported.
- Quota support: accounts can have individual quota expressed as max total size and/or max number of files.
- Bandwidth throttling is supported, with distinct settings for upload and download.
- Per user maximum concurrent sessions.
- Per user permissions: list directories content, upload, download, delete, rename, create directories, create symlinks can be enabled or disabled.
- Per user files/folders ownership: you can map all the users to the system account that runs SFTPGo (all platforms are supported) or you can run SFTPGo as root user and map each user or group of users to a different system account (*NIX only).
- Configurable custom commands and/or HTTP notifications on upload, download, delete or rename.
- Automatically terminating idle connections.
- Atomic uploads are configurable.
- Optional SCP support.
- REST API for users and quota management and real time reports for the active connections with possibility of forcibly closing a connection.
- Configuration is a your choice: JSON, TOML, YAML, HCL, envfile are supported.
- Log files are accurate and they are saved in the easily parsable JSON format.

## Platforms

SFTPGo is developed and tested on Linux. After each commit the code is automatically built and tested on Linux and macOS using Travis CI.
Regularly the test cases are manually executed and pass on Windows. Other UNIX variants such as *BSD should work too.

## Requirements

- Go 1.12 or higher.
- A suitable SQL server or key/value store to use as data provider: PostreSQL 9.4+ or MySQL 5.6+ or SQLite 3.x or bbolt 1.3.x

## Installation

Simple install the package to your [$GOPATH](https://github.com/golang/go/wiki/GOPATH "GOPATH") with the [go tool](https://golang.org/cmd/go/ "go command") from shell:

```bash
$ go get -u github.com/drakkan/sftpgo
```

Make sure [Git is installed](https://git-scm.com/downloads) on your machine and in your system's `PATH`.

SFTPGo depends on [go-sqlite3](https://github.com/mattn/go-sqlite3) that is a CGO package and so it requires a `C` compiler at build time.
On Linux and macOS a compiler is easy to install or already installed, on Windows you need to download [MinGW-w64](https://sourceforge.net/projects/mingw-w64/files/) and build SFTPGo from its command prompt.

The compiler is a build time only dependency, it is not not required at runtime.

If you don't need SQLite, you can also get/build SFTPGo setting the environment variable `GCO_ENABLED` to 0, this way SQLite support will be disabled but PostgreSQL, MySQL and bbolt will work and you don't need a `C` compiler for building.

Version info, such as git commit and build date, can be embedded setting the following string variables at build time:

- `github.com/drakkan/sftpgo/utils.commit`
- `github.com/drakkan/sftpgo/utils.date`

For example you can build using the following command:

```bash
go build -i -ldflags "-s -w -X github.com/drakkan/sftpgo/utils.commit=`git describe --always --dirty` -X github.com/drakkan/sftpgo/utils.date=`date -u +%FT%TZ`" -o sftpgo
```

and you will get a version that includes git commit and build date like this one:

```bash
sftpgo -v
SFTPGo version: 0.9.0-dev-90607d4-dirty-2019-08-08T19:28:36Z
```

For Linux, a `systemd` sample [service](https://github.com/drakkan/sftpgo/tree/master/init/sftpgo.service "systemd service") can be found inside the source tree.

Alternately you can use distro packages:

- Arch Linux PKGBUILD is available on [AUR](https://aur.archlinux.org/packages/sftpgo/ "SFTPGo")

For macOS a `launchd` sample [service](https://github.com/drakkan/sftpgo/tree/master/init/com.github.drakkan.sftpgo.plist "launchd plist") can be found inside the source tree. The `launchd` plist assumes that `sftpgo` has `/usr/local/opt/sftpgo` as base directory. 

## Configuration

The `sftpgo` executable can be used this way:

```bash
Usage:
  sftpgo [command]

Available Commands:
  help        Help about any command
  serve       Start the SFTP Server

Flags:
  -h, --help      help for sftpgo
  -v, --version
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

Sample SQL scripts to create the required database structure can be found inside the source tree [sql](https://github.com/drakkan/sftpgo/tree/master/sql "sql") directory. The SQL scripts filename's is, by convention, the date as `YYYYMMDD` and the suffix `.sql`. You need to apply all the SQL scripts for your database ordered by name, for example `20190706.sql` must be applied before `20190728.sql` and so on.

The `sftpgo` configuration file contains the following sections:

- **"sftpd"**, the configuration for the SFTP server
    - `bind_port`, integer. The port used for serving SFTP requests. Default: 2022
    - `bind_address`, string. Leave blank to listen on all available network interfaces. Default: ""
    - `idle_timeout`, integer. Time in minutes after which an idle client will be disconnected. 0 menas disabled. Default: 15
    - `max_auth_tries` integer. Maximum number of authentication attempts permitted per connection. If set to a negative number, the number of attempts are unlimited. If set to zero, the number of attempts are limited to 6.
    - `umask`, string. Umask for the new files and directories. This setting has no effect on Windows. Default: "0022"
    - `banner`, string. Identification string used by the server. Default "SFTPGo"
    - `upload_mode` integer. 0 means standard, the files are uploaded directly to the requested path. 1 means atomic: files are uploaded to a temporary path and renamed to the requested path when the client ends the upload. Atomic mode avoids problems such as a web server that serves partial files when the files are being uploaded. In atomic mode if there is an upload error the temporary file is deleted and so the requested upload path will not contain a partial file.
    - `actions`, struct. It contains the command to execute and/or the HTTP URL to notify and the trigger conditions
        - `execute_on`, list of strings. Valid values are `download`, `upload`, `delete`, `rename`. On folder deletion a `delete` notification will be sent for each deleted file. Actions will be not executed if an error is detected and so a partial file is uploaded or downloaded. Leave empty to disable actions.
        - `command`, string. Absolute path to the command to execute. Leave empty to disable. The command is invoked with the following arguments:
            - `action`, any valid `execute_on` string
            - `username`, user who did the action
            - `path` to the affected file. For `rename` action this is the old file name
            - `target_path`, non empty for `rename` action, this is the new file name
        - `http_notification_url`, a valid URL. An HTTP GET request will be executed to this URL. Leave empty to disable. The query string will contain the following parameters that have the same meaning of the command's arguments:
            - `action`
            - `username`
            - `path`
            - `target_path`, added for `rename` action only
    - `keys`, struct array. It contains the daemon's private keys. If empty or missing the daemon will search or try to generate `id_rsa` in the configuration directory.
        - `private_key`, path to the private key file. It can be a path relative to the config dir or an absolute one.
    - `enable_scp`, boolean. Default disabled. Set to `true` to enable SCP support. SCP is an experimental feature, we have our own SCP implementation since we can't rely on `scp` system command to proper handle permissions, quota and user's home dir restrictions. The SCP protocol is quite simple but there is no official docs about it, so we need more testing and feedbacks before enabling it by default. We may not handle some borderline cases or have sneaky bugs. Please do accurate tests yourself before enabling SCP and let us known if something does not work as expected for your use cases. SCP between two remote hosts is supported using the `-3` scp option.
    - `kex_algorithms`, list of strings. Available KEX (Key Exchange) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L46 "Supported kex algos")
    - `ciphers`, list of strings. Allowed ciphers. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L28 "Supported ciphers")
    - `macs`, list of strings. available MAC (message authentication code) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L76 "Supported MACs")
    - `login_banner_file`, path to the login banner file. The contents of the specified file, if any, are sent to the remote user before authentication is allowed. It can be a path relative to the config dir or an absolute one. Leave empty to send no login banner
- **"data_provider"**, the configuration for the data provider
    - `driver`, string. Supported drivers are `sqlite`, `mysql`, `postgresql`, `bolt`
    - `name`, string. Database name. For driver `sqlite` this can be the database name relative to the config dir or the absolute path to the SQLite database.
    - `host`, string. Database host. Leave empty for driver `sqlite` and `bolt`
    - `port`, integer. Database port. Leave empty for driver `sqlite` and `bolt`
    - `username`, string. Database user. Leave empty for driver `sqlite` and `bolt`
    - `password`, string. Database password. Leave empty for driver `sqlite` and `bolt`
    - `sslmode`, integer. Used for drivers `mysql` and `postgresql`. 0 disable SSL/TLS connections, 1 require ssl, 2 set ssl mode to `verify-ca` for driver `postgresql` and `skip-verify` for driver `mysql`, 3 set ssl mode to `verify-full` for driver `postgresql` and `preferred` for driver `mysql`
    - `connectionstring`, string. Provide a custom database connection string. If not empty this connection string will be used instead of build one using the previous parameters. Leave empty for driver `bolt`
    - `users_table`, string. Database table for SFTP users
    - `manage_users`, integer. Set to 0 to disable users management, 1 to enable
    - `track_quota`, integer. Set the preferred way to track users quota between the following choices:
        - 0, disable quota tracking. REST API to scan user dir and update quota will do nothing
        - 1, quota is updated each time a user upload or delete a file even if the user has no quota restrictions
        - 2, quota is updated each time a user upload or delete a file but only for users with quota restrictions. With this configuration the "quota scan" REST API can still be used to periodically update space usage for users without quota restrictions
- **"httpd"**, the configuration for the HTTP server used to serve REST API
    - `bind_port`, integer. The port used for serving HTTP requests. Set to 0 to disable HTTP server. Default: 8080
    - `bind_address`, string. Leave blank to listen on all available network interfaces. Default: "127.0.0.1"

Here is a full example showing the default config in JSON format:

```json
{
  "sftpd": {
    "bind_port": 2022,
    "bind_address": "",
    "idle_timeout": 15,
    "max_auth_tries": 0,
    "umask": "0022",
    "banner": "SFTPGo",
    "actions": {
      "execute_on": [],
      "command": "",
      "http_notification_url": ""
    },
    "keys": [],
    "enable_scp": false
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
    "track_quota": 2
  },
  "httpd": {
    "bind_port": 8080,
    "bind_address": "127.0.0.1"
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

```bash
sftpgo serve
```

## Account's configuration properties

For each account the following properties can be configured:

- `username`
- `password` used for password authentication. For users created using SFTPGo REST API if the password has no known hashing algo prefix it will be stored using argon2id. SFTPGo supports checking passwords stored with bcrypt and pbkdf2 too. For pbkdf2 the supported format is `$<algo>$<iterations>$<salt>$<hashed pwd base64 encoded>`, where algo is `pbkdf2-sha1` or `pbkdf2-sha256` or `pbkdf2-sha512`. For example the `pbkdf2-sha256` of the word `password` using 150000 iterations and `E86a9YMX3zC7` as salt must be stored as `$pbkdf2-sha256$150000$E86a9YMX3zC7$R5J62hsSq+pYw00hLLPKBbcGXmq7fj5+/M0IFoYtZbo=`. For bcrypt the format must be the one supported by golang's [crypto/bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) package, for example the password `secret` with cost `14` must be stored as `$2a$14$ajq8Q7fbtFRQvXpdCq7Jcuy.Rx1h/L4J60Otx.gyNLbAYctGMJ9tK`. Using the REST API you can send a password hashed as bcrypt or pbkdf2 and it will be stored as is.
- `public_keys` array of public keys. At least one public key or the password is mandatory.
- `home_dir` The user cannot upload or download files outside this directory. Must be an absolute path
- `uid`, `gid`. If sftpgo runs as root system user then the created files and directories will be assigned to this system uid/gid. Ignored on windows and if sftpgo runs as non root user: in this case files and directories for all SFTP users will be owned by the system user that runs sftpgo.
- `max_sessions` maximum concurrent sessions. 0 means unlimited
- `quota_size` maximum size allowed as bytes. 0 means unlimited
- `quota_files` maximum number of files allowed. 0 means unlimited
- `permissions` the following permissions are supported:
    - `*` all permission are granted
    - `list` list items is allowed
    - `download` download files is allowed
    - `upload` upload files is allowed
    - `delete` delete files or directories is allowed
    - `rename` rename files or directories is allowed
    - `create_dirs` create directories is allowed
    - `create_symlinks` create symbolic links is allowed
- `upload_bandwidth` maximum upload bandwidth as KB/s, 0 means unlimited
- `download_bandwidth` maximum download bandwidth as KB/s, 0 means unlimited

These properties are stored inside the data provider. If you want to use your existing accounts, you can create a database view. Since a view is read only, you have to disable user management and quota tracking so SFTPGo will never try to write to the view.

## REST API

SFTPGo exposes REST API to manage users and quota and to get real time reports for the active connections with possibility of forcibly closing a connection.

If quota tracking is enabled in `sftpgo` configuration file, then the used size and number of files are updated each time a file is added/removed. If files are added/removed not using SFTP or if you change `track_quota` from `2` to `1`, you can rescan the user home dir and update the used quota using the REST API.

REST API is designed to run on localhost or on a trusted network, if you need HTTPS or authentication you can setup a reverse proxy using an HTTP Server such as Apache or NGNIX.

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

The OpenAPI 3 schema for the exposed API can be found inside the source tree: [openapi.yaml](https://github.com/drakkan/sftpgo/tree/master/api/schema/openapi.yaml "OpenAPI 3 specs").

A sample CLI client for the REST API can be found inside the source tree [scripts](https://github.com/drakkan/sftpgo/tree/master/scripts "scripts") directory.

You can also generate your own REST client, in your preferred programming language or even bash scripts, using an OpenAPI generator such as [swagger-codegen](https://github.com/swagger-api/swagger-codegen) or [OpenAPI Generator](https://openapi-generator.tech/)

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
    - `sender` string. `Rename`, `Rmdir`, `Mkdir`, `Symlink`, `Remove`
    - `level` string
    - `username`, string
    - `file_path` string
    - `target_path` string
    - `connection_id` string. Unique connection identifier
    - `protocol` string. `SFTP` or `SCP`
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

Some code was initially taken from [Pterodactyl sftp server](https://github.com/pterodactyl/sftp-server)

## License

GNU GPLv3
