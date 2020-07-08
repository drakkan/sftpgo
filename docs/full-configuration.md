# Configuring SFTPGo

## Command line options

The SFTPGo executable can be used this way:

```console
Usage:
  sftpgo [command]

Available Commands:
  gen          A collection of useful generators
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

- `--config-dir` string. Location of the config dir. This directory should contain the configuration file and is used as the base directory for any files that use a relative path (eg. the private keys for the SFTP server, the SQLite or bblot database if you use SQLite or bbolt as data provider). The default value is "." or the value of `SFTPGO_CONFIG_DIR` environment variable.
- `--config-file` string. Name of the configuration file. It must be the name of a file stored in `config-dir`, not the absolute path to the configuration file. The specified file name must have no extension because we automatically append JSON, YAML, TOML, HCL and Java extensions when we search for the file. The default value is "sftpgo" (and therefore `sftpgo.json`, `sftpgo.yaml` and so on are searched) or the value of `SFTPGO_CONFIG_FILE` environment variable.
- `--log-compress` boolean. Determine if the rotated log files should be compressed using gzip. Default `false` or the value of `SFTPGO_LOG_COMPRESS` environment variable (1 or `true`, 0 or `false`). It is unused if `log-file-path` is empty.
- `--log-file-path` string. Location for the log file, default "sftpgo.log" or the value of `SFTPGO_LOG_FILE_PATH` environment variable. Leave empty to write logs to the standard error.
- `--log-max-age` int. Maximum number of days to retain old log files. Default 28 or the value of `SFTPGO_LOG_MAX_AGE` environment variable. It is unused if `log-file-path` is empty.
- `--log-max-backups` int. Maximum number of old log files to retain. Default 5 or the value of `SFTPGO_LOG_MAX_BACKUPS` environment variable. It is unused if `log-file-path` is empty.
- `--log-max-size` int. Maximum size in megabytes of the log file before it gets rotated. Default 10 or the value of `SFTPGO_LOG_MAX_SIZE` environment variable. It is unused if `log-file-path` is empty.
- `--log-verbose` boolean. Enable verbose logs. Default `true` or the value of `SFTPGO_LOG_VERBOSE` environment variable (1 or `true`, 0 or `false`).

Log file can be rotated on demand sending a `SIGUSR1` signal on Unix based systems and using the command `sftpgo service rotatelogs` on Windows.

If you don't configure any private host key, the daemon will use `id_rsa` and `id_ecdsa` in the configuration directory. If these files don't exist, the daemon will attempt to autogenerate them (if the user that executes SFTPGo has write access to the `config-dir`). The server supports any private key format supported by [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/keys.go#L33).

The `gen` command allows to generate completion scripts for your shell and man pages. Currently the man pages visual representation is wrong, take a look at this upstream [bug](https://github.com/spf13/cobra/issues/1049) for more details.

## Configuration file

The configuration file contains the following sections:

- **"sftpd"**, the configuration for the SFTP server
  - `bind_port`, integer. The port used for serving SFTP requests. Default: 2022
  - `bind_address`, string. Leave blank to listen on all available network interfaces. Default: ""
  - `idle_timeout`, integer. Time in minutes after which an idle client will be disconnected. 0 means disabled. Default: 15
  - `max_auth_tries` integer. Maximum number of authentication attempts permitted per connection. If set to a negative number, the number of attempts is unlimited. If set to zero, the number of attempts are limited to 6.
  - `umask`, string. Umask for the new files and directories. This setting has no effect on Windows. Default: "0022"
  - `banner`, string. Identification string used by the server. Leave empty to use the default banner. Default `SFTPGo_<version>`, for example `SSH-2.0-SFTPGo_0.9.5`
  - `upload_mode` integer. 0 means standard: the files are uploaded directly to the requested path. 1 means atomic: files are uploaded to a temporary path and renamed to the requested path when the client ends the upload. Atomic mode avoids problems such as a web server that serves partial files when the files are being uploaded. In atomic mode, if there is an upload error, the temporary file is deleted and so the requested upload path will not contain a partial file. 2 means atomic with resume support: same as atomic but if there is an upload error, the temporary file is renamed to the requested path and not deleted. This way, a client can reconnect and resume the upload.
  - `actions`, struct. It contains the command to execute and/or the HTTP URL to notify and the trigger conditions. See the "Custom Actions" paragraph for more details
    - `execute_on`, list of strings. Valid values are `download`, `upload`, `pre-delete`, `delete`, `rename`, `ssh_cmd`. Leave empty to disable actions.
    - `command`, string. Deprecated please use `hook`.
    - `http_notification_url`, a valid URL. Deprecated please use `hook`.
    - `hook`, string. Absolute path to the command to execute or HTTP URL to notify.
  - `keys`, struct array. Deprecated, please use `host_keys`.
    - `private_key`, path to the private key file. It can be a path relative to the config dir or an absolute one.
  - `host_keys`, list of strings. It contains the daemon's private host keys. Each host key can be defined as a path relative to the configuration directory or an absolute one. If empty, the daemon will search or try to generate `id_rsa` and `id_ecdsa` keys inside the configuration directory. If you configure absolute paths to files named `id_rsa` and/or `id_ecdsa` then SFTPGo will try to generate these keys using the default settings.
  - `kex_algorithms`, list of strings. Available KEX (Key Exchange) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L46 "Supported kex algos")
  - `ciphers`, list of strings. Allowed ciphers. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L28 "Supported ciphers")
  - `macs`, list of strings. Available MAC (message authentication code) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L84 "Supported MACs")
  - `trusted_user_ca_keys`, list of public keys paths of certificate authorities that are trusted to sign user certificates for authentication. The paths can be absolute or relative to the configuration directory.
  - `login_banner_file`, path to the login banner file. The contents of the specified file, if any, are sent to the remote user before authentication is allowed. It can be a path relative to the config dir or an absolute one. Leave empty to disable login banner.
  - `setstat_mode`, integer. 0 means "normal mode": requests for changing permissions, owner/group and access/modification times are executed. 1 means "ignore mode": requests for changing permissions, owner/group and access/modification times are silently ignored.
  - `enabled_ssh_commands`, list of enabled SSH commands. `*` enables all supported commands. More information can be found [here](./ssh-commands.md).
  - `keyboard_interactive_auth_program`, string. Deprecated, please use `keyboard_interactive_auth_hook`.
  - `keyboard_interactive_auth_hook`, string. Absolute path to an external program or an HTTP URL to invoke for keyboard interactive authentication. See the "Keyboard Interactive Authentication" paragraph for more details.
  - `proxy_protocol`, integer. Support for [HAProxy PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt). If you are running SFTPGo behind a proxy server such as HAProxy, AWS ELB or NGNIX, you can enable the proxy protocol. It provides a convenient way to safely transport connection information such as a client's address across multiple layers of NAT or TCP proxies to get the real client IP address instead of the proxy IP. Both protocol versions 1 and 2 are supported. If the proxy protocol is enabled in SFTPGo then you have to enable the protocol in your proxy configuration too. For example, for HAProxy, add `send-proxy` or `send-proxy-v2` to each server configuration line. The following modes are supported:
    - 0, disabled
    - 1, enabled. Proxy header will be used and requests without proxy header will be accepted
    - 2, required. Proxy header will be used and requests without proxy header will be rejected
  - `proxy_allowed`, List of IP addresses and IP ranges allowed to send the proxy header:
    - If `proxy_protocol` is set to 1 and we receive a proxy header from an IP that is not in the list then the connection will be accepted and the header will be ignored
    - If `proxy_protocol` is set to 2 and we receive a proxy header from an IP that is not in the list then the connection will be rejected
- **"data_provider"**, the configuration for the data provider
  - `driver`, string. Supported drivers are `sqlite`, `mysql`, `postgresql`, `bolt`, `memory`
  - `name`, string. Database name. For driver `sqlite` this can be the database name relative to the config dir or the absolute path to the SQLite database. For driver `memory` this is the (optional) path relative to the config dir or the absolute path to the users dump, obtained using the `dumpdata` REST API, to load. This dump will be loaded at startup and can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows. The `memory` provider will not modify the provided file so quota usage and last login will not be persisted
  - `host`, string. Database host. Leave empty for drivers `sqlite`, `bolt` and `memory`
  - `port`, integer. Database port. Leave empty for drivers `sqlite`, `bolt` and `memory`
  - `username`, string. Database user. Leave empty for drivers `sqlite`, `bolt` and `memory`
  - `password`, string. Database password. Leave empty for drivers `sqlite`, `bolt` and `memory`
  - `sslmode`, integer. Used for drivers `mysql` and `postgresql`. 0 disable SSL/TLS connections, 1 require ssl, 2 set ssl mode to `verify-ca` for driver `postgresql` and `skip-verify` for driver `mysql`, 3 set ssl mode to `verify-full` for driver `postgresql` and `preferred` for driver `mysql`
  - `connectionstring`, string. Provide a custom database connection string. If not empty, this connection string will be used instead of building one using the previous parameters. Leave empty for drivers `bolt` and `memory`
  - `sql_tables_prefix`, string. Prefix for SQL tables
  - `manage_users`, integer. Set to 0 to disable users management, 1 to enable
  - `track_quota`, integer. Set the preferred mode to track users quota between the following choices:
    - 0, disable quota tracking. REST API to scan users home directories/virtual folders and update quota will do nothing
    - 1, quota is updated each time a user uploads or deletes a file, even if the user has no quota restrictions
    - 2, quota is updated each time a user uploads or deletes a file, but only for users with quota restrictions and for virtual folders. With this configuration, the `quota scan` and `folder_quota_scan` REST API can still be used to periodically update space usage for users without quota restrictions and for folders
  - `pool_size`, integer. Sets the maximum number of open connections for `mysql` and `postgresql` driver. Default 0 (unlimited)
  - `users_base_dir`, string. Users default base directory. If no home dir is defined while adding a new user, and this value is a valid absolute path, then the user home dir will be automatically defined as the path obtained joining the base dir and the username
  - `actions`, struct. It contains the command to execute and/or the HTTP URL to notify and the trigger conditions. See the "Custom Actions" paragraph for more details
    - `execute_on`, list of strings. Valid values are `add`, `update`, `delete`. `update` action will not be fired for internal updates such as the last login or the user quota fields.
    - `command`, string. Deprecated please use `hook`.
    - `http_notification_url`, a valid URL. Deprecated please use `hook`.
    - `hook`, string. Absolute path to the command to execute or HTTP URL to notify.
  - `external_auth_program`, string. Deprecated, please use `external_auth_hook`.
  - `external_auth_hook`, string. Absolute path to an external program or an HTTP URL to invoke for users authentication. See the "External Authentication" paragraph for more details. Leave empty to disable.
  - `external_auth_scope`, integer. 0 means all supported authetication scopes (passwords, public keys and keyboard interactive). 1 means passwords only. 2 means public keys only. 4 means key keyboard interactive only. The flags can be combined, for example 6 means public keys and keyboard interactive
  - `credentials_path`, string. It defines the directory for storing user provided credential files such as Google Cloud Storage credentials. This can be an absolute path or a path relative to the config dir
  - `pre_login_program`, string. Deprecated, please use `pre_login_hook`.
  - `pre_login_hook`, string. Absolute path to an external program or an HTTP URL to invoke to modify user details just before the login. See the "Dynamic user modification" paragraph for more details. Leave empty to disable.
- **"httpd"**, the configuration for the HTTP server used to serve REST API and to expose the built-in web interface
  - `bind_port`, integer. The port used for serving HTTP requests. Set to 0 to disable HTTP server. Default: 8080
  - `bind_address`, string. Leave blank to listen on all available network interfaces. Default: "127.0.0.1"
  - `templates_path`, string. Path to the HTML web templates. This can be an absolute path or a path relative to the config dir
  - `static_files_path`, string. Path to the static files for the web interface. This can be an absolute path or a path relative to the config dir. If both `templates_path` and `static_files_path` are empty the built-in web interface will be disabled
  - `backups_path`, string. Path to the backup directory. This can be an absolute path or a path relative to the config dir. We don't allow backups in arbitrary paths for security reasons
  - `auth_user_file`, string. Path to a file used to store usernames and passwords for basic authentication. This can be an absolute path or a path relative to the config dir. We support HTTP basic authentication, and the file format must conform to the one generated using the Apache `htpasswd` tool. The supported password formats are bcrypt (`$2y$` prefix) and md5 crypt (`$apr1$` prefix). If empty, HTTP authentication is disabled.
  - `certificate_file`, string. Certificate for HTTPS. This can be an absolute path or a path relative to the config dir.
  - `certificate_key_file`, string. Private key matching the above certificate. This can be an absolute path or a path relative to the config dir. If both the certificate and the private key are provided, the server will expect HTTPS connections. Certificate and key files can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows.
- **"http"**, the configuration for HTTP clients. HTTP clients are used for executing hooks such as the ones used for custom actions, external authentication and pre-login user modifications
  - `timeout`, integer. Timeout specifies a time limit, in seconds, for requests.
  - `ca_certificates`, list of strings. List of paths to extra CA certificates to trust. The paths can be absolute or relative to the config dir. Adding trusted CA certificates is a convenient way to use self-signed certificates without defeating the purpose of using TLS.
  - `skip_tls_verify`, boolean. if enabled the HTTP client accepts any TLS certificate presented by the server and any host name in that certificate. In this mode, TLS is susceptible to man-in-the-middle attacks. This should be used only for testing.

A full example showing the default config (in JSON format) can be found [here](../sftpgo.json).

If you want to use a private host key that use an algorithm/setting different from the auto generated RSA/ECDSA keys, or more than two private keys, you can generate your own keys and replace the empty `keys` array with something like this:

```json
"host_keys": [
  "id_rsa",
  "id_ecdsa",
  "id_ed25519"
]
```

where `id_rsa`, `id_ecdsa` and `id_ed25519`, in this example, are files containing your generated keys. You can use absolute paths or paths relative to the configuration directory.

If you want the default host keys generation in a directory different from the config dir, please specify absolute paths to files named `id_rsa` or `id_ecdsa` like this:

```json
"host_keys": [
  "/etc/sftpgo/keys/id_rsa",
  "/etc/sftpgo/keys/id_ecdsa"
]
```

then SFTPGo will try to create `id_rsa` and `id_ecdsa`, if they are missing, inside the existing directory `/etc/sftpgo/keys`.

The configuration can be read from JSON, TOML, YAML, HCL, envfile and Java properties config files. If your `config-file` flag is set to `sftpgo` (default value), you need to create a configuration file called `sftpgo.json` or `sftpgo.yaml` and so on inside `config-dir`.

## Environment variables

You can also override all the available configuration options using environment variables. SFTPGo will check for environment variables with a name matching the key uppercased and prefixed with the `SFTPGO_`. You need to use `__` to traverse a struct.

Let's see some examples:

- To set sftpd `bind_port`, you need to define the env var `SFTPGO_SFTPD__BIND_PORT`
- To set the `execute_on` actions, you need to define the env var `SFTPGO_SFTPD__ACTIONS__EXECUTE_ON`. For example `SFTPGO_SFTPD__ACTIONS__EXECUTE_ON=upload,download`

Please note that, to override configuration options with environment variables, a configuration file containing the options to override is required. You can, for example, deploy the default configuration file and then override the options you need to customize using environment variables.
