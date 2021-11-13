# Configuring SFTPGo

## Command line options

The SFTPGo executable can be used this way:

```console
Usage:
  sftpgo [command]

Available Commands:
  gen            A collection of useful generators
  help           Help about any command
  initprovider   Initialize and/or updates the configured data provider
  portable       Serve a single directory/account
  revertprovider Revert the configured data provider to a previous version
  serve          Start the SFTPGo service
  smtptest       Test the SMTP configuration
  startsubsys    Use sftpgo as SFTP file transfer subsystem

Flags:
  -h, --help      help for sftpgo
  -v, --version

 Use "sftpgo [command] --help" for more information about a command
```

The `serve` command supports the following flags:

- `--config-dir` string. Location of the config dir. This directory is used as the base for files with a relative path, eg. the private keys for the SFTP server or the SQLite database if you use SQLite as data provider. The configuration file, if not explicitly set, is looked for in this dir. We support reading from JSON, TOML, YAML, HCL, envfile and Java properties config files. The default config file name is `sftpgo` and therefore `sftpgo.json`, `sftpgo.yaml` and so on are searched. The default value is the working directory (".") or the value of `SFTPGO_CONFIG_DIR` environment variable.
- `--config-file` string. This flag explicitly defines the path, name and extension of the config file. If must be an absolute path or a path relative to the configuration directory. The specified file name must have a supported extension (JSON, YAML, TOML, HCL or Java properties). The default value is empty or the value of `SFTPGO_CONFIG_FILE` environment variable.
- `--loaddata-from` string. Load users and folders from this file. The file must be specified as absolute path and it must contain a backup obtained using the `dumpdata` REST API or compatible content. The default value is empty or the value of `SFTPGO_LOADDATA_FROM` environment variable.
- `--loaddata-clean` boolean. Determine if the loaddata-from file should be removed after a successful load. Default `false` or the value of `SFTPGO_LOADDATA_CLEAN` environment variable (1 or `true`, 0 or `false`).
- `--loaddata-mode`, integer. Restore mode for data to load. 0 means new users are added, existing users are updated. 1 means new users are added, existing users are not modified. Default 1 or the value of `SFTPGO_LOADDATA_MODE` environment variable.
- `--loaddata-scan`, integer. Quota scan mode after data load. 0 means no quota scan. 1 means quota scan. 2 means scan quota if the user has quota restrictions. Default 0 or the value of `SFTPGO_LOADDATA_QUOTA_SCAN` environment variable.
- `--log-compress` boolean. Determine if the rotated log files should be compressed using gzip. Default `false` or the value of `SFTPGO_LOG_COMPRESS` environment variable (1 or `true`, 0 or `false`). It is unused if `log-file-path` is empty.
- `--log-file-path` string. Location for the log file, default "sftpgo.log" or the value of `SFTPGO_LOG_FILE_PATH` environment variable. Leave empty to write logs to the standard error.
- `--log-max-age` int. Maximum number of days to retain old log files. Default 28 or the value of `SFTPGO_LOG_MAX_AGE` environment variable. It is unused if `log-file-path` is empty.
- `--log-max-backups` int. Maximum number of old log files to retain. Default 5 or the value of `SFTPGO_LOG_MAX_BACKUPS` environment variable. It is unused if `log-file-path` is empty.
- `--log-max-size` int. Maximum size in megabytes of the log file before it gets rotated. Default 10 or the value of `SFTPGO_LOG_MAX_SIZE` environment variable. It is unused if `log-file-path` is empty.
- `--log-verbose` boolean. Enable verbose logs. Default `true` or the value of `SFTPGO_LOG_VERBOSE` environment variable (1 or `true`, 0 or `false`).
- `--log-utc-time` boolean. Enable UTC time for logging. Default `false` or the value of `SFTPGO_LOG_UTC_TIME` environment variable (1 or `true`, 0 or `false`)

Log file can be rotated on demand sending a `SIGUSR1` signal on Unix based systems and using the command `sftpgo service rotatelogs` on Windows.

If you don't configure any private host key, the daemon will use `id_rsa`, `id_ecdsa` and `id_ed25519` in the configuration directory. If these files don't exist, the daemon will attempt to autogenerate them. The server supports any private key format supported by [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/keys.go#L33).

The `gen` command allows to generate completion scripts for your shell and man pages.

## Configuration file

The configuration file contains the following sections:

- **"common"**, configuration parameters shared among all the supported protocols
  - `idle_timeout`, integer. Time in minutes after which an idle client will be disconnected. 0 means disabled. Default: 15
  - `upload_mode` integer. 0 means standard: the files are uploaded directly to the requested path. 1 means atomic: files are uploaded to a temporary path and renamed to the requested path when the client ends the upload. Atomic mode avoids problems such as a web server that serves partial files when the files are being uploaded. In atomic mode, if there is an upload error, the temporary file is deleted and so the requested upload path will not contain a partial file. 2 means atomic with resume support: same as atomic but if there is an upload error, the temporary file is renamed to the requested path and not deleted. This way, a client can reconnect and resume the upload. Default: 0
  - `actions`, struct. It contains the command to execute and/or the HTTP URL to notify and the trigger conditions. See [Custom Actions](./custom-actions.md) for more details
    - `execute_on`, list of strings. Valid values are `pre-download`, `download`, `pre-upload`, `upload`, `pre-delete`, `delete`, `rename`, `ssh_cmd`. Leave empty to disable actions.
    - `execute_sync`, list of strings. Actions to be performed synchronously. The `pre-delete` action is always executed synchronously while the other ones are asynchronous. Executing an action synchronously means that SFTPGo will not return a result code to the client (which is waiting for it) until your hook have completed its execution. Leave empty to execute only the `pre-delete` hook synchronously
    - `hook`, string. Absolute path to the command to execute or HTTP URL to notify.
  - `setstat_mode`, integer. 0 means "normal mode": requests for changing permissions, owner/group and access/modification times are executed. 1 means "ignore mode": requests for changing permissions, owner/group and access/modification times are silently ignored. 2 means "ignore mode for cloud based filesystems": requests for changing permissions, owner/group and access/modification times are silently ignored for cloud filesystems and executed for local filesystem.
  - `temp_path`, string. Defines the path for temporary files such as those used for atomic uploads or file pipes. If you set this option you must make sure that the defined path exists, is accessible for writing by the user running SFTPGo, and is on the same filesystem as the users home directories otherwise the renaming for atomic uploads will become a copy and therefore may take a long time. The temporary files are not namespaced. The default is generally fine. Leave empty for the default.
  - `proxy_protocol`, integer. Support for [HAProxy PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt). If you are running SFTPGo behind a proxy server such as HAProxy, AWS ELB or NGNIX, you can enable the proxy protocol. It provides a convenient way to safely transport connection information such as a client's address across multiple layers of NAT or TCP proxies to get the real client IP address instead of the proxy IP. Both protocol versions 1 and 2 are supported. If the proxy protocol is enabled in SFTPGo then you have to enable the protocol in your proxy configuration too. For example, for HAProxy, add `send-proxy` or `send-proxy-v2` to each server configuration line. The following modes are supported:
    - 0, disabled
    - 1, enabled. If the upstream IP is not allowed to send a proxy header the header be ignored. Using this mode does not mean that we can accept connections with and without the proxy header. We always try to read the proxy header and we ignore it if the upstream IP is not allowed to send a proxy header
    - 2, required. If the upstream IP is not allowed to send a proxy header the connection will be rejected
  - `proxy_allowed`, List of IP addresses and IP ranges allowed to send the proxy header:
    - If `proxy_protocol` is set to 1 and we receive a proxy header from an IP that is not in the list then the connection will be accepted and the header will be ignored
    - If `proxy_protocol` is set to 2 and we receive a proxy header from an IP that is not in the list then the connection will be rejected
  - `startup_hook`, string. Absolute path to an external program or an HTTP URL to invoke as soon as SFTPGo starts. If you define an HTTP URL it will be invoked using a `GET` request. Please note that SFTPGo services may not yet be available when this hook is run. Leave empty do disable
  - `post_connect_hook`, string. Absolute path to the command to execute or HTTP URL to notify. See [Post-connect hook](./post-connect-hook.md) for more details. Leave empty to disable
  - `post_disconnect_hook`, string. Absolute path to the command to execute or HTTP URL to notify. See [Post-disconnect hook](./post-disconnect-hook.md) for more details. Leave empty to disable
  - `data_retention_hook`, string. Absolute path to the command to execute or HTTP URL to notify. See [Data retention hook](./data-retention-hook.md) for more details. Leave empty to disable
  - `max_total_connections`, integer. Maximum number of concurrent client connections. 0 means unlimited. Default: 0.
  - `max_per_host_connections`, integer.  Maximum number of concurrent client connections from the same host (IP). If the defender is enabled, exceeding this limit will generate `score_limit_exceeded` events and thus hosts that repeatedly exceed the max allowed connections can be automatically blocked. 0 means unlimited. Default: 20.
  - `defender`, struct containing the defender configuration. See [Defender](./defender.md) for more details.
    - `enabled`, boolean. Default `false`.
    - `ban_time`, integer. Ban time in minutes.
    - `ban_time_increment`, integer. Ban time increment, as a percentage, if a banned host tries to connect again.
    - `threshold`, integer. Threshold value for banning a client.
    - `score_invalid`, integer. Score for invalid login attempts, eg. non-existent user accounts or client disconnected for inactivity without authentication attempts.
    - `score_valid`, integer. Score for valid login attempts, eg. user accounts that exist.
    - `score_limit_exceeded`, integer. Score for hosts that exceeded the configured rate limits or the maximum, per-host, allowed connections.
    - `observation_time`, integer. Defines the time window, in minutes, for tracking client errors. A host is banned if it has exceeded the defined threshold during the last observation time minutes.
    - `entries_soft_limit`, integer.
    - `entries_hard_limit`, integer. The number of banned IPs and host scores kept in memory will vary between the soft and hard limit.
    - `safelist_file`, string. Path to a file containing a list of ip addresses and/or networks to never ban.
    - `blocklist_file`, string. Path to a file containing a list of ip addresses and/or networks to always ban. The lists can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows. An host that is already banned will not be automatically unbanned if you put it inside the safe list, you have to unban it using the REST API.
  - `rate_limiters`, list of structs containing the rate limiters configuration. Take a look [here](./rate-limiting.md) for more details. Each struct has the following fields:
    - `average`, integer. Average defines the maximum rate allowed. 0 means disabled. Default: 0
    - `period`, integer. Period defines the period as milliseconds. The rate is actually defined by dividing average by period Default: 1000 (1 second).
    - `burst`, integer. Burst defines the maximum number of requests allowed to go through in the same arbitrarily small period of time. Default: 1
    - `type`, integer. 1 means a global rate limiter, independent from the source host. 2 means a per-ip rate limiter. Default: 2
    - `protocols`, list of strings. Available protocols are `SSH`, `FTP`, `DAV`, `HTTP`. By default all supported protocols are enabled
    - `allow_list`, list of IP addresses and IP ranges excluded from rate limiting. Default: empty
    - `generate_defender_events`, boolean. If `true`, the defender is enabled, and this is not a global rate limiter, a new defender event will be generated each time the configured limit is exceeded. Default `false`
    - `entries_soft_limit`, integer.
    - `entries_hard_limit`, integer. The number of per-ip rate limiters kept in memory will vary between the soft and hard limit
- **"sftpd"**, the configuration for the SFTP server
  - `bindings`, list of structs. Each struct has the following fields:
    - `port`, integer. The port used for serving SFTP requests. 0 means disabled. Default: 2022
    - `address`, string. Leave blank to listen on all available network interfaces. Default: ""
    - `apply_proxy_config`, boolean. If enabled the common proxy configuration, if any, will be applied. Default `true`
  - `max_auth_tries` integer. Maximum number of authentication attempts permitted per connection. If set to a negative number, the number of attempts is unlimited. If set to zero, the number of attempts is limited to 6.
  - `banner`, string. Identification string used by the server. Leave empty to use the default banner. Default `SFTPGo_<version>`, for example `SSH-2.0-SFTPGo_0.9.5`
  - `host_keys`, list of strings. It contains the daemon's private host keys. Each host key can be defined as a path relative to the configuration directory or an absolute one. If empty, the daemon will search or try to generate `id_rsa`, `id_ecdsa` and `id_ed25519` keys inside the configuration directory. If you configure absolute paths to files named `id_rsa`, `id_ecdsa` and/or `id_ed25519` then SFTPGo will try to generate these keys using the default settings.
  - `kex_algorithms`, list of strings. Available KEX (Key Exchange) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [`crypto/ssh`](https://github.com/golang/crypto/blob/master/ssh/common.go#L46 "Supported kex algos")
  - `ciphers`, list of strings. Allowed ciphers. Leave empty to use default values. The supported values can be found here: [crypto/ssh](https://github.com/golang/crypto/blob/master/ssh/common.go#L28 "Supported ciphers")
  - `macs`, list of strings. Available MAC (message authentication code) algorithms in preference order. Leave empty to use default values. The supported values can be found here: [crypto/ssh](https://github.com/golang/crypto/blob/master/ssh/common.go#L84 "Supported MACs")
  - `trusted_user_ca_keys`, list of public keys paths of certificate authorities that are trusted to sign user certificates for authentication. The paths can be absolute or relative to the configuration directory.
  - `login_banner_file`, path to the login banner file. The contents of the specified file, if any, are sent to the remote user before authentication is allowed. It can be a path relative to the config dir or an absolute one. Leave empty to disable login banner.
  - `enabled_ssh_commands`, list of enabled SSH commands. `*` enables all supported commands. More information can be found [here](./ssh-commands.md).
  - `keyboard_interactive_authentication`, boolean. This setting specifies whether keyboard interactive authentication is allowed. If no keyboard interactive hook or auth plugin is defined the default is to prompt for the user password and then the one time authentication code, if defined. Default: `false`.
  - `keyboard_interactive_auth_hook`, string. Absolute path to an external program or an HTTP URL to invoke for keyboard interactive authentication. See [Keyboard Interactive Authentication](./keyboard-interactive.md) for more details.
  - `password_authentication`, boolean. Set to false to disable password authentication. This setting will disable multi-step authentication method using public key + password too. It is useful for public key only configurations if you need to manage old clients that will not attempt to authenticate with public keys if the password login method is advertised. Default: `true`.
  - `folder_prefix`, string. Virtual root folder prefix to include in all file operations (ex: `/files`). The virtual paths used for per-directory permissions, file patterns etc. must not include the folder prefix. The prefix is only applied to SFTP requests (in SFTP server mode), SCP and other SSH commands will be automatically disabled if you configure a prefix.  The prefix is ignored while running as OpenSSH's SFTP subsystem. This setting can help some specific migrations from SFTP servers based on OpenSSH and it is not recommended for general usage. Default: empty.
- **"ftpd"**, the configuration for the FTP server
  - `bindings`, list of structs. Each struct has the following fields:
    - `port`, integer. The port used for serving FTP requests. 0 means disabled. Default: 0.
    - `address`, string. Leave blank to listen on all available network interfaces. Default: "".
    - `apply_proxy_config`, boolean. If enabled the common proxy configuration, if any, will be applied. Please note that we expect the proxy header on control and data connections. Default `true`.
    - `tls_mode`, integer. 0 means accept both cleartext and encrypted sessions. 1 means TLS is required for both control and data connection. 2 means implicit TLS. Do not enable this blindly, please check that a proper TLS config is in place if you set `tls_mode` is different from 0.
    - `force_passive_ip`, ip address. External IP address to expose for passive connections. Leavy empty to autodetect. If not empty, it must be a valid IPv4 address. Defaut: "".
    - `client_auth_type`, integer. Set to `1` to require a client certificate and verify it. Set to `2` to request a client certificate during the TLS handshake and verify it if given, in this mode the client is allowed not to send a certificate. At least one certification authority must be defined in order to verify client certificates. If no certification authority is defined, this setting is ignored. Default: 0.
    - `tls_cipher_suites`, list of strings. List of supported cipher suites for TLS version 1.2. If empty, a default list of secure cipher suites is used, with a preference order based on hardware performance. Note that TLS 1.3 ciphersuites are not configurable. The supported ciphersuites names are defined [here](https://github.com/golang/go/blob/master/src/crypto/tls/cipher_suites.go#L52). Any invalid name will be silently ignored. The order matters, the ciphers listed first will be the preferred ones. Default: empty.
    - `passive_connections_security`, integer. Defines the security checks for passive data connections. Set to `0` to require matching peer IP addresses of control and data connection. Set to `1` to disable any checks. Please note that if you run the FTP service behind a proxy you must enable the proxy protocol for control and data connections. Default: `0`.
    - `active_connections_security`, integer. Defines the security checks for active data connections. The supported values are the same as described for `passive_connections_security`. Please note that disabling the security checks you will make the FTP service vulnerable to bounce attacks on active data connections, so change the default value only if you are on a trusted/internal network. Default: `0`.
    - `debug`, boolean. If enabled any FTP command will be logged. This will generate a lot of logs. Enable only if you are investigating a client compatibility issue or something similar. You shouldn't leave this setting enabled for production servers. Default `false`.
  - `banner`, string. Greeting banner displayed when a connection first comes in. Leave empty to use the default banner. Default `SFTPGo <version> ready`, for example `SFTPGo 1.0.0-dev ready`.
  - `banner_file`, path to the banner file. The contents of the specified file, if any, are displayed when someone connects to the server. It can be a path relative to the config dir or an absolute one. If set, it overrides the banner string provided by the `banner` option. Leave empty to disable.
  - `active_transfers_port_non_20`, boolean. Do not impose the port 20 for active data transfers. Enabling this option allows to run SFTPGo with less privilege. Default: false.
  - `passive_port_range`, struct containing the key `start` and `end`. Port Range for data connections. Random if not specified. Default range is 50000-50100.
  - `disable_active_mode`, boolean. Set to `true` to disable active FTP, default `false`.
  - `enable_site`, boolean. Set to true to enable the FTP SITE command. We support `chmod` and `symlink` if SITE support is enabled. Default `false`
  - `hash_support`, integer. Set to `1` to enable FTP commands that allow to calculate the hash value of files. These FTP commands will be enabled: `HASH`, `XCRC`, `MD5/XMD5`, `XSHA/XSHA1`, `XSHA256`, `XSHA512`. Please keep in mind that to calculate the hash we need to read the whole file, for remote backends this means downloading the file, for the encrypted backend this means decrypting the file. Default `0`.
  - `combine_support`, integer. Set to 1 to enable support for the non standard `COMB` FTP command. Combine is only supported for local filesystem, for cloud backends it has no advantage as it will download the partial files and will upload the combined one. Cloud backends natively support multipart uploads. Default `0`.
  - `certificate_file`, string. Certificate for FTPS. This can be an absolute path or a path relative to the config dir.
  - `certificate_key_file`, string. Private key matching the above certificate. This can be an absolute path or a path relative to the config dir. A certificate and the private key are required to enable explicit and implicit TLS. Certificate and key files can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows.
  - `ca_certificates`, list of strings. Set of root certificate authorities to be used to verify client certificates.
  - `ca_revocation_lists`, list of strings. Set a revocation lists, one for each root CA, to be used to check if a client certificate has been revoked. The revocation lists can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows.
- **"webdavd"**, the configuration for the WebDAV server, more info [here](./webdav.md)
  - `bindings`, list of structs. Each struct has the following fields:
    - `port`, integer. The port used for serving WebDAV requests. 0 means disabled. Default: 0.
    - `address`, string. Leave blank to listen on all available network interfaces. Default: "".
    - `enable_https`, boolean. Set to `true` and provide both a certificate and a key file to enable HTTPS connection for this binding. Default `false`.
    - `client_auth_type`, integer. Set to `1` to require a client certificate and verify it. Set to `2` to request a client certificate during the TLS handshake and verify it if given, in this mode the client is allowed not to send a certificate. At least one certification authority must be defined in order to verify client certificates. If no certification authority is defined, this setting is ignored. Default: 0.
    - `tls_cipher_suites`, list of strings. List of supported cipher suites for TLS version 1.2. If empty, a default list of secure cipher suites is used, with a preference order based on hardware performance. Note that TLS 1.3 ciphersuites are not configurable. The supported ciphersuites names are defined [here](https://github.com/golang/go/blob/master/src/crypto/tls/cipher_suites.go#L52). Any invalid name will be silently ignored. The order matters, the ciphers listed first will be the preferred ones. Default: empty.
    - `prefix`, string. Prefix for WebDAV resources, if empty WebDAV resources will be available at the `/` URI. If defined it must be an absolute URI, for example `/dav`. Default: "".
    - `proxy_allowed`, list of IP addresses and IP ranges allowed to set `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP` headers. Any of the indicated headers, if set on requests from a connection address not in this list, will be silently ignored. Default: empty.
  - `certificate_file`, string. Certificate for WebDAV over HTTPS. This can be an absolute path or a path relative to the config dir.
  - `certificate_key_file`, string. Private key matching the above certificate. This can be an absolute path or a path relative to the config dir. A certificate and a private key are required to enable HTTPS connections. Certificate and key files can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows.
  - `ca_certificates`, list of strings. Set of root certificate authorities to be used to verify client certificates.
  - `ca_revocation_lists`, list of strings. Set a revocation lists, one for each root CA, to be used to check if a client certificate has been revoked. The revocation lists can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows.
  - `cors` struct containing CORS configuration. SFTPGo uses [Go CORS handler](https://github.com/rs/cors), please refer to upstream documentation for fields meaning and their default values.
    - `enabled`, boolean, set to true to enable CORS.
    - `allowed_origins`, list of strings.
    - `allowed_methods`, list of strings.
    - `allowed_headers`, list of strings.
    - `exposed_headers`, list of strings.
    - `allow_credentials` boolean.
    - `max_age`, integer.
  - `cache` struct containing cache configuration for the authenticated users.
    - `enabled`, boolean, set to true to enable user caching. Default: true.
    - `expiration_time`, integer. Expiration time, in minutes, for the cached users. 0 means unlimited. Default: 0.
    - `max_size`, integer. Maximum number of users to cache. 0 means unlimited. Default: 50.
- **"data_provider"**, the configuration for the data provider
  - `driver`, string. Supported drivers are `sqlite`, `mysql`, `postgresql`, `cockroachdb`, `bolt`, `memory`
  - `name`, string. Database name. For driver `sqlite` this can be the database name relative to the config dir or the absolute path to the SQLite database. For driver `memory` this is the (optional) path relative to the config dir or the absolute path to the provider dump, obtained using the `dumpdata` REST API, to load. This dump will be loaded at startup and can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows. The `memory` provider will not modify the provided file so quota usage and last login will not be persisted. If you plan to use a SQLite database over a `cifs` network share (this is not recommended in general) you must use the `nobrl` mount option otherwise you will get the `database is locked` error. Some users reported that the `bolt` provider works fine over `cifs` shares.
  - `host`, string. Database host. Leave empty for drivers `sqlite`, `bolt` and `memory`
  - `port`, integer. Database port. Leave empty for drivers `sqlite`, `bolt` and `memory`
  - `username`, string. Database user. Leave empty for drivers `sqlite`, `bolt` and `memory`
  - `password`, string. Database password. Leave empty for drivers `sqlite`, `bolt` and `memory`
  - `sslmode`, integer. Used for drivers `mysql` and `postgresql`. 0 disable SSL/TLS connections, 1 require ssl, 2 set ssl mode to `verify-ca` for driver `postgresql` and `skip-verify` for driver `mysql`, 3 set ssl mode to `verify-full` for driver `postgresql` and `preferred` for driver `mysql`
  - `connection_string`, string. Provide a custom database connection string. If not empty, this connection string will be used instead of building one using the previous parameters. Leave empty for drivers `bolt` and `memory`
  - `sql_tables_prefix`, string. Prefix for SQL tables
  - `track_quota`, integer. Set the preferred mode to track users quota between the following choices:
    - 0, disable quota tracking. REST API to scan users home directories/virtual folders and update quota will do nothing
    - 1, quota is updated each time a user uploads or deletes a file, even if the user has no quota restrictions
    - 2, quota is updated each time a user uploads or deletes a file, but only for users with quota restrictions and for virtual folders. With this configuration, the `quota scan` and `folder_quota_scan` REST API can still be used to periodically update space usage for users without quota restrictions and for folders
  - `delayed_quota_update`, integer. This configuration parameter defines the number of seconds to accumulate quota updates. If there are a lot of close uploads, accumulating quota updates can save you many queries to the data provider. If you want to track quotas, a scheduled quota update is recommended in any case, the stored quota may be incorrect for several reasons, such as an unexpected shutdown while uploading files, temporary provider failures, files copied outside of SFTPGo, and so on. You could use the [quotascan example](../examples/quotascan) as a starting point. 0 means immediate quota update.
  - `pool_size`, integer. Sets the maximum number of open connections for `mysql` and `postgresql` driver. Default 0 (unlimited)
  - `users_base_dir`, string. Users default base directory. If no home dir is defined while adding a new user, and this value is a valid absolute path, then the user home dir will be automatically defined as the path obtained joining the base dir and the username
  - `actions`, struct. It contains the command to execute and/or the HTTP URL to notify and the trigger conditions. See [Custom Actions](./custom-actions.md) for more details
    - `execute_on`, list of strings. Valid values are `add`, `update`, `delete`. `update` action will not be fired for internal updates such as the last login or the user quota fields.
    - `execute_for`, list of strings. Defines the provider objects that trigger the action. Valid values are `user`, `admin`, `api_key`.
    - `hook`, string. Absolute path to the command to execute or HTTP URL to notify.
  - `external_auth_hook`, string. Absolute path to an external program or an HTTP URL to invoke for users authentication. See [External Authentication](./external-auth.md) for more details. Leave empty to disable.
  - `external_auth_scope`, integer. 0 means all supported authentication scopes (passwords, public keys and keyboard interactive). 1 means passwords only. 2 means public keys only. 4 means key keyboard interactive only. 8 means TLS certificate. The flags can be combined, for example 6 means public keys and keyboard interactive
  - `credentials_path`, string. It defines the directory for storing user provided credential files such as Google Cloud Storage credentials. This can be an absolute path or a path relative to the config dir
  - `prefer_database_credentials`, boolean. When true, users' Google Cloud Storage credentials will be written to the data provider instead of disk, though pre-existing credentials on disk will be used as a fallback. When false, they will be written to the directory specified by `credentials_path`.
  - `pre_login_hook`, string. Absolute path to an external program or an HTTP URL to invoke to modify user details just before the login. See [Dynamic user modification](./dynamic-user-mod.md) for more details. Leave empty to disable.
  - `post_login_hook`, string. Absolute path to an external program or an HTTP URL to invoke to notify a successful or failed login. See [Post-login hook](./post-login-hook.md) for more details. Leave empty to disable.
  - `post_login_scope`, defines the scope for the post-login hook. 0 means notify both failed and successful logins. 1 means notify failed logins. 2 means notify successful logins.
  - `check_password_hook`, string.  Absolute path to an external program or an HTTP URL to invoke to check the user provided password. See [Check password hook](./check-password-hook.md) for more details. Leave empty to disable.
  - `check_password_scope`, defines the scope for the check password hook. 0 means all protocols, 1 means SSH, 2 means FTP, 4 means WebDAV. You can combine the scopes, for example 6 means FTP and WebDAV.
  - `password_hashing`, struct. It contains the configuration parameters to be used to generate the password hash. SFTPGo can verify passwords in several formats and uses, by default, the `bcrypt` algorithm to hash passwords in plain-text before storing them inside the data provider. These options allow you to customize how the hash is generated.
    - `argon2_options`, struct containing the options for argon2id hashing algorithm. The `memory` and `iterations` parameters control the computational cost of hashing the password. The higher these figures are, the greater the cost of generating the hash and the longer the runtime. It also follows that the greater the cost will be for any attacker trying to guess the password. If the code is running on a machine with multiple cores, then you can decrease the runtime without reducing the cost by increasing the `parallelism` parameter. This controls the number of threads that the work is spread across.
      - `memory`, unsigned integer. The amount of memory used by the algorithm (in kibibytes). Default: 65536.
      - `iterations`, unsigned integer. The number of iterations over the memory. Default: 1.
      - `parallelism`. unsigned 8 bit integer. The number of threads (or lanes) used by the algorithm. Default: 2.
    - `bcrypt_options`, struct containing the options for bcrypt hashing algorithm
      - `cost`, integer between 4 and 31. Default: 10
    - `algo`, string. Algorithm to use for hashing passwords. Available algorithms: `argon2id`, `bcrypt`. For bcrypt hashing we use the `$2a$` prefix. Default: `bcrypt`
  - `password_validation` struct. It defines the password validation rules for admins and protocol users.
    - `admins`, struct. It defines the password validation rules for SFTPGo admins.
      - `min_entropy`, float. Defines the minimum password entropy. Take a looke [here](https://github.com/wagslane/go-password-validator#what-entropy-value-should-i-use) for more details. `0` means disabled, any password will be accepted. Default: `0`.
    - `users`, struct. It defines the password validation rules for SFTPGo protocol users.
      - `min_entropy`, float. Default: `0`.
  - `password_caching`, boolean. Verifying argon2id passwords has a high memory and computational cost, verifying bcrypt passwords has a high computational cost, by enabling, in memory, password caching you reduce these costs. Default: `true`
  - `update_mode`, integer. Defines how the database will be initialized/updated. 0 means automatically. 1 means manually using the initprovider sub-command.
  - `skip_natural_keys_validation`, boolean. If `true` you can use any UTF-8 character for natural keys as username, admin name, folder name. These keys are used in URIs for REST API and Web admin. If `false` only unreserved URI characters are allowed: ALPHA / DIGIT / "-" / "." / "_" / "~". Default: `false`.
  - `create_default_admin`, boolean. Before you can use SFTPGo you need to create an admin account. If you open the admin web UI, a setup screen will guide you in creating the first admin account. You can automatically create the first admin account by enabling this setting and setting the environment variables `SFTPGO_DEFAULT_ADMIN_USERNAME` and `SFTPGO_DEFAULT_ADMIN_PASSWORD`. You can also create the first admin by loading initial data. This setting has no effect if an admin account is already found within the data provider. Default `false`.
  - `is_shared`, integer. If the data provider is shared across multiple SFTPGo instances, set this parameter to `1`. `MySQL`, `PostgreSQL` and `CockroachDB` can be shared, this setting is ignored for other data providers. For shared data providers, SFTPGo periodically reloads the latest updated users, based on the `updated_at` field, and updates its internal caches if users are updated from a different instance. This check, if enabled, is executed every 10 minutes. Default: `0`.
- **"httpd"**, the configuration for the HTTP server used to serve REST API and to expose the built-in web interface
  - `bindings`, list of structs. Each struct has the following fields:
    - `port`, integer. The port used for serving HTTP requests. Default: 8080.
    - `address`, string. Leave blank to listen on all available network interfaces. On *NIX you can specify an absolute path to listen on a Unix-domain socket Default: "127.0.0.1".
    - `enable_web_admin`, boolean. Set to `false` to disable the built-in web admin for this binding. You also need to define `templates_path` and `static_files_path` to use the built-in web admin interface. Default `true`.
    - `enable_web_client`, boolean. Set to `false` to disable the built-in web client for this binding. You also need to define `templates_path` and `static_files_path` to use the built-in web client interface. Default `true`.
    - `enable_https`, boolean. Set to `true` and provide both a certificate and a key file to enable HTTPS connection for this binding. Default `false`.
    - `client_auth_type`, integer. Set to `1` to require client certificate authentication in addition to JWT/Web authentication. You need to define at least a certificate authority for this to work. Default: 0.
    - `tls_cipher_suites`, list of strings. List of supported cipher suites for TLS version 1.2. If empty, a default list of secure cipher suites is used, with a preference order based on hardware performance. Note that TLS 1.3 ciphersuites are not configurable. The supported ciphersuites names are defined [here](https://github.com/golang/go/blob/master/src/crypto/tls/cipher_suites.go#L52). Any invalid name will be silently ignored. The order matters, the ciphers listed first will be the preferred ones. Default: empty.
    - `proxy_allowed`, list of IP addresses and IP ranges allowed to set `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `CF-Connecting-IP`, `True-Client-IP` headers. Any of the indicated headers, if set on requests from a connection address not in this list, will be silently ignored. Default: empty.
    - `hide_login_url`, integer. If both web admin and web client are enabled each login page will show a link to the other one. This setting allows to hide this link. 0 means that the login links are displayed on both admin and client login page. This is the default. 1 means that the login link to the web client login page is hidden on admin login page. 2 means that the login link to the web admin login page is hidden on client login page. The flags can be combined, for example 3 will disable both login links.
  - `templates_path`, string. Path to the HTML web templates. This can be an absolute path or a path relative to the config dir
  - `static_files_path`, string. Path to the static files for the web interface. This can be an absolute path or a path relative to the config dir. If both `templates_path` and `static_files_path` are empty the built-in web interface will be disabled
  - `backups_path`, string. Path to the backup directory. This can be an absolute path or a path relative to the config dir. We don't allow backups in arbitrary paths for security reasons
  - `web_root`, string.  Defines a base URL for the web admin and client interfaces. If empty web admin and client resources will be available at the root ("/") URI. If defined it must be an absolute URI or it will be ignored
  - `certificate_file`, string. Certificate for HTTPS. This can be an absolute path or a path relative to the config dir.
  - `certificate_key_file`, string. Private key matching the above certificate. This can be an absolute path or a path relative to the config dir. If both the certificate and the private key are provided, the server will expect HTTPS connections. Certificate and key files can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows.
  - `ca_certificates`, list of strings. Set of root certificate authorities to be used to verify client certificates.
  - `ca_revocation_lists`, list of strings. Set a revocation lists, one for each root CA, to be used to check if a client certificate has been revoked. The revocation lists can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows.
  - `signing_passphrase`, string. Passphrase to use to derive the signing key for JWT and CSRF tokens. If empty a random signing key will be generated each time SFTPGo starts. If you set a signing passphrase you should consider rotating it periodically for added security.
  - `max_upload_file_size`, integer. Defines the maximum request body size, in bytes, for Web Client/API HTTP upload requests. 0 means no limit. Default: 1048576000.
  - `cors` struct containing CORS configuration. SFTPGo uses [Go CORS handler](https://github.com/rs/cors), please refer to upstream documentation for fields meaning and their default values.
    - `enabled`, boolean, set to true to enable CORS.
    - `allowed_origins`, list of strings.
    - `allowed_methods`, list of strings.
    - `allowed_headers`, list of strings.
    - `exposed_headers`, list of strings.
    - `allow_credentials` boolean.
    - `max_age`, integer.
- **"telemetry"**, the configuration for the telemetry server, more details [below](#telemetry-server)
  - `bind_port`, integer. The port used for serving HTTP requests. Set to 0 to disable HTTP server. Default: 10000
  - `bind_address`, string. Leave blank to listen on all available network interfaces. On \*NIX you can specify an absolute path to listen on a Unix-domain socket. Default: "127.0.0.1"
  - `enable_profiler`, boolean. Enable the built-in profiler. Default `false`
  - `auth_user_file`, string. Path to a file used to store usernames and passwords for basic authentication. This can be an absolute path or a path relative to the config dir. We support HTTP basic authentication, and the file format must conform to the one generated using the Apache `htpasswd` tool. The supported password formats are bcrypt (`$2y$` prefix) and md5 crypt (`$apr1$` prefix). If empty, HTTP authentication is disabled. Authentication will be always disabled for the `/healthz` endpoint.
  - `certificate_file`, string. Certificate for HTTPS. This can be an absolute path or a path relative to the config dir.
  - `certificate_key_file`, string. Private key matching the above certificate. This can be an absolute path or a path relative to the config dir. If both the certificate and the private key are provided, the server will expect HTTPS connections. Certificate and key files can be reloaded on demand sending a `SIGHUP` signal on Unix based systems and a `paramchange` request to the running service on Windows.
  - `tls_cipher_suites`, list of strings. List of supported cipher suites for TLS version 1.2. If empty, a default list of secure cipher suites is used, with a preference order based on hardware performance. Note that TLS 1.3 ciphersuites are not configurable. The supported ciphersuites names are defined [here](https://github.com/golang/go/blob/master/src/crypto/tls/cipher_suites.go#L52). Any invalid name will be silently ignored. The order matters, the ciphers listed first will be the preferred ones. Default: empty.
- **"http"**, the configuration for HTTP clients. HTTP clients are used for executing hooks. Some hooks use a retryable HTTP client, for these hooks you can configure the time between retries and the number of retries. Please check the hook specific documentation to understand which hooks use a retryable HTTP client.
  - `timeout`, float. Timeout specifies a time limit, in seconds, for requests. For requests with retries this is the timeout for a single request
  - `retry_wait_min`, integer. Defines the minimum waiting time between attempts in seconds.
  - `retry_wait_max`, integer. Defines the maximum waiting time between attempts in seconds. The backoff algorithm will perform exponential backoff based on the attempt number and limited by the provided minimum and maximum durations.
  - `retry_max`, integer. Defines the maximum number of retries if the first request fails.
  - `ca_certificates`, list of strings. List of paths to extra CA certificates to trust. The paths can be absolute or relative to the config dir. Adding trusted CA certificates is a convenient way to use self-signed certificates without defeating the purpose of using TLS.
  - `certificates`, list of certificate for mutual TLS. Each certificate is a struct with the following fields:
    - `cert`, string. Path to the certificate file. The path can be absolute or relative to the config dir.
    - `key`, string. Path to the key file. The path can be absolute or relative to the config dir.
  - `skip_tls_verify`, boolean. if enabled the HTTP client accepts any TLS certificate presented by the server and any host name in that certificate. In this mode, TLS is susceptible to man-in-the-middle attacks. This should be used only for testing.
  - `headers`, list of structs. You can define a list of http headers to add to each hook. Each struct has the following fields:
    - `key`, string
    - `value`, string. The header is silently ignored if `key` or `value` are empty
    - `url`, string, optional. If not empty, the header will be added only if the request URL starts with the one specified here
- **kms**, configuration for the Key Management Service, more details can be found [here](./kms.md)
  - `secrets`
    - `url`, string. Defines the URI to the KMS service. Default: empty.
    - `master_key`, string. Defines the master encryption key as string. If not empty, it takes precedence over `master_key_path`. Default: empty.
    - `master_key_path, string. Defines the absolute path to a file containing the master encryption key. Default: empty.
- **mfa**, multi-factor authentication settings
  - `totp`, list of struct that define settings for time-based one time passwords (RFC 6238). Each struct has the following fields:
    - `name`, string. Unique configuration name. This name should not be changed if there are users or admins using the configuration. The name is not exposed to the authentication apps. Default: `Default`.
    - `issuer`, string. Name of the issuing Organization/Company. Default: `SFTPGo`.
    - `algo`, string. Algorithm to use for HMAC. The supported algorithms are: `sha1`, `sha256`, `sha512`. Currently Google Authenticator app on iPhone seems to only support `sha1`, please check the compatibility with your target apps/device before setting a different algorithm. You can also define multiple configurations, for example one that uses `sha256` or `sha512` and another one that uses `sha1` and instruct your users to use the appropriate configuration for their devices/apps. The algorithm should not be changed if there are users or admins using the configuration. Default: `sha1`.
- **smtp**, SMTP configuration enables SFTPGo email sending capabilities
  - `host`, string. Location of SMTP email server. Leavy empty to disable email sending capabilities. Default: empty.
  - `port`, integer. Port of SMTP email server.
  - `from`, string. From address, for example `SFTPGo <sftpgo@example.com>`. Many SMTP servers reject emails without a `From` header so, if not set, SFTPGo will try to use the username as fallback, this may or may not be appropriate. Default: empty
  - `user`, string. SMTP username. Default: empty
  - `password`, string. SMTP password. Leaving both username and password empty the SMTP authentication will be disabled. Default: empty
  - `auth_type`, integer. 0 means `Plain`, 1 means `Login`, 2 means `CRAM-MD5`. Default: `0`.
  - `encryption`, integer. 0 means no encryption, 1 means `TLS`, 2 means `STARTTLS`. Default: `0`.
  - `domain`, string. Domain to use for `HELO` command, if empty `localhost` will be used. Default: empty.
  - `templates_path`, string. Path to the email templates. This can be an absolute path or a path relative to the config dir. Templates are searched within a subdirectory named "email" in the specified path. You can customize the email templates by simply specifying an alternate path and putting your custom templates there.
- **plugins**, list of external plugins. Each plugin is configured using a struct with the following fields:
  - `type`, string. Defines the plugin type. Supported types: `notifier`, `kms`, `auth`.
  - `notifier_options`, struct. Defines the options for notifier plugins.
    - `fs_events`, list of strings. Defines the filesystem events that will be notified to this plugin.
    - `provider_events`, list of strings. Defines the provider events that will be notified to this plugin.
    - `provider_objects`, list if strings. Defines the provider objects that will be notified to this plugin.
    - `retry_max_time`, integer. Defines the maximum number of seconds an event can be late. SFTPGo adds a timestamp to each event and add to an internal queue any events that a the plugin fails to handle (the plugin returns an error or it is not running). If a plugin fails to handle an event that is too late, based on this configuration, it will be discarded. SFTPGo will try to resend queued events every 30 seconds. 0 means no retry.
    - `retry_queue_max_size`, integer. Defines the maximum number of events that the internal queue can hold. Once the queue is full, the events that cannot be sent to the plugin will be discarded. 0 means no limit.
  - `kms_options`, struct. Defines the options for kms plugins.
    - `scheme`, string. KMS scheme. Supported schemes are: `awskms`, `gcpkms`, `hashivault`, `azurekeyvault`.
    - `encrypted_status`, string. Encrypted status for a KMS secret. Supported statuses are: `AWS`, `GCP`, `VaultTransit`, `AzureKeyVault`.
  - `auth_options`, struct. Defines the options for auth plugins.
    - `scope`, integer. 1 means passwords only. 2 means public keys only. 4 means key keyboard interactive only. 8 means TLS certificate. The flags can be combined, for example 6 means public keys and keyboard interactive. The scope must be explicit, `0` is not a valid option.
  - `cmd`, string. Path to the plugin executable.
  - `args`, list of strings. Optional arguments to pass to the plugin executable.
  - `sha256sum`, string. SHA256 checksum for the plugin executable. If not empty it will be used to verify the integrity of the executable.
  - `auto_mtls`, boolean. If enabled the client and the server automatically negotiate mutual TLS for transport authentication. This ensures that only the original client will be allowed to connect to the server, and all other connections will be rejected. The client will also refuse to connect to any server that isn't the original instance started by the client.

Please note that the plugin system is experimental, the exposed configuration parameters and interfaces may change in a backward incompatible way in future.

A full example showing the default config (in JSON format) can be found [here](../sftpgo.json).

If you want to use a private host key that uses an algorithm/setting different from the auto generated RSA/ECDSA keys, or more than two private keys, you can generate your own keys and replace the empty `keys` array with something like this:

```json
"host_keys": [
  "id_rsa",
  "id_ecdsa",
  "id_ed25519"
]
```

where `id_rsa`, `id_ecdsa` and `id_ed25519`, in this example, are files containing your generated keys. You can use absolute paths or paths relative to the configuration directory specified via the `--config-dir` serve flag. By default the configuration directory is the working directory.

If you want the default host keys generation in a directory different from the config dir, please specify absolute paths to files named `id_rsa`, `id_ecdsa` or `id_ed25519` like this:

```json
"host_keys": [
  "/etc/sftpgo/keys/id_rsa",
  "/etc/sftpgo/keys/id_ecdsa",
  "/etc/sftpgo/keys/id_ed25519"
]
```

then SFTPGo will try to create `id_rsa`, `id_ecdsa` and `id_ed25519`, if they are missing, inside the directory `/etc/sftpgo/keys`.

The configuration can be read from JSON, TOML, YAML, HCL, envfile and Java properties config files. If your `config-file` flag is set to `sftpgo` (default value), you need to create a configuration file called `sftpgo.json` or `sftpgo.yaml` and so on inside `config-dir`.

## Environment variables

You can also override all the available configuration options using environment variables. SFTPGo will check for environment variables with a name matching the key uppercased and prefixed with the `SFTPGO_`. You need to use `__` to traverse a struct.

Let's see some examples:

- To set the `port` for the first sftpd binding, you need to define the env var `SFTPGO_SFTPD__BINDINGS__0__PORT`
- To set the `execute_on` actions, you need to define the env var `SFTPGO_COMMON__ACTIONS__EXECUTE_ON`. For example `SFTPGO_COMMON__ACTIONS__EXECUTE_ON=upload,download`

On some hardware you can get faster SFTP performance by replacing the Go `crypto/sha256` implementation with [sha256-simd](https://github.com/minio/sha256-simd).

The performances of SHA256 is relevant for clients using AES CTR ciphers and `hmac-sha2-256` as Message Authentication Code (MAC).

Up to 2.0.x versions SFTPGo automatically used `sha256-simd` but over the time the standard Go implementation improved a lot and now is faster than `sha256-simd` on some CPUs.
You can select `sha256-simd` setting the environment variable `SFTPGO_MINIO_SHA256_SIMD` to `1`.

 `sha256-simd` is particularly useful if you have an Intel CPU with SHA extensions or an ARM CPU with Cryptography Extensions.

## Binding to privileged ports

On Linux, if you want to use Internet domain privileged ports (port numbers less than 1024) instead of running the SFTPGo service as root user you can set the `cap_net_bind_service` capability on the `sftpgo` binary. To set the capability you can use the following command:

```shell
$ sudo setcap cap_net_bind_service=+ep /usr/bin/sftpgo
# Check that the capability is added
$ getcap /usr/bin/sftpgo
/usr/bin/sftpgo cap_net_bind_service=ep
```

Now you can use privileged ports such as 21, 22, 443 etc.. without running the SFTPGo service as root user. You have to set the `cap_net_bind_service` capability each time you update the `sftpgo` binary.

An alternative method is to use `iptables`, for example you run the SFTP service on port `2022` and redirect traffic from port `22` to port `2022`:

```shell
sudo iptables -t nat -A PREROUTING -d <ip> -p tcp --dport 22 -m addrtype --dst-type LOCAL -j DNAT --to-destination <ip>:2022
sudo iptables -t nat -A OUTPUT     -d <ip> -p tcp --dport 22 -m addrtype --dst-type LOCAL -j DNAT --to-destination <ip>:2022
```

## Telemetry Server

The telemetry server exposes the following endpoints:

- `/healthz`, health information (for health checks)
- `/metrics`, Prometheus metrics
- `/debug/pprof`, if enabled via the `enable_profiler` configuration key, for profiling, more details [here](./profiling.md)
