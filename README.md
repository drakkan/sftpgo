# SFTPGo

![CI Status](https://github.com/drakkan/sftpgo/workflows/CI/badge.svg?branch=master&event=push)
[![Code Coverage](https://codecov.io/gh/drakkan/sftpgo/branch/master/graph/badge.svg)](https://codecov.io/gh/drakkan/sftpgo/branch/master)
[![Go Report Card](https://goreportcard.com/badge/github.com/drakkan/sftpgo)](https://goreportcard.com/report/github.com/drakkan/sftpgo)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Docker Pulls](https://img.shields.io/docker/pulls/drakkan/sftpgo)](https://hub.docker.com/r/drakkan/sftpgo)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

Fully featured and highly configurable SFTP server with optional FTP/S and WebDAV support, written in Go.
It can serve local filesystem, S3 (compatible) Object Storage, Google Cloud Storage and Azure Blob Storage.

## Features

- SFTPGo uses virtual accounts stored inside a "data provider".
- SQLite, MySQL, PostgreSQL, bbolt (key/value store in pure Go) and in-memory data providers are supported.
- Each account is chrooted to its home directory.
- Public key and password authentication. Multiple public keys per user are supported.
- SSH user [certificate authentication](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.8).
- Keyboard interactive authentication. You can easily setup a customizable multi-factor authentication.
- Partial authentication. You can configure multi-step authentication requiring, for example, the user password after successful public key authentication.
- Per user authentication methods. You can configure the allowed authentication methods for each user.
- Custom authentication via external programs/HTTP API is supported.
- [Data At Rest Encryption](./docs/dare.md) is supported.
- Dynamic user modification before login via external programs/HTTP API is supported.
- Quota support: accounts can have individual quota expressed as max total size and/or max number of files.
- Bandwidth throttling is supported, with distinct settings for upload and download.
- Per user maximum concurrent sessions.
- Per user and per directory permission management: list directory contents, upload, overwrite, download, delete, rename, create directories, create symlinks, change owner/group and mode, change access and modification times.
- Per user files/folders ownership mapping: you can map all the users to the system account that runs SFTPGo (all platforms are supported) or you can run SFTPGo as root user and map each user or group of users to a different system account (\*NIX only).
- Per user IP filters are supported: login can be restricted to specific ranges of IP addresses or to a specific IP address.
- Per user and per directory shell like patterns filters are supported: files can be allowed or denied based on shell like patterns.
- Virtual folders are supported: directories outside the user home directory can be exposed as virtual folders.
- Configurable custom commands and/or HTTP notifications on file upload, download, pre-delete, delete, rename, on SSH commands and on user add, update and delete.
- Automatically terminating idle connections.
- Atomic uploads are configurable.
- Support for Git repositories over SSH.
- SCP and rsync are supported.
- FTP/S is supported. You can configure the FTP service to require TLS for both control and data connections.
- [WebDAV](./docs/webdav.md) is supported.
- Support for serving local filesystem, S3 Compatible Object Storage and Google Cloud Storage over SFTP/SCP/FTP/WebDAV.
- Per user protocols restrictions. You can configure the allowed protocols (SSH/FTP/WebDAV) for each user.
- [Prometheus metrics](./docs/metrics.md) are exposed.
- Support for HAProxy PROXY protocol: you can proxy and/or load balance the SFTP/SCP/FTP/WebDAV service without losing the information about the client's address.
- [REST API](./docs/rest-api.md) for users and folders management, backup, restore and real time reports of the active connections with possibility of forcibly closing a connection.
- [Web based administration interface](./docs/web-admin.md) to easily manage users, folders and connections.
- Easy [migration](./examples/rest-api-cli#convert-users-from-other-stores) from Linux system user accounts.
- [Portable mode](./docs/portable-mode.md): a convenient way to share a single directory on demand.
- [SFTP subsystem mode](./docs/sftp-subsystem.md): you can use SFTPGo as OpenSSH's SFTP subsystem.
- Performance analysis using built-in [profiler](./docs/profiling.md).
- Configuration format is at your choice: JSON, TOML, YAML, HCL, envfile are supported.
- Log files are accurate and they are saved in the easily parsable JSON format ([more information](./docs/logs.md)).

## Platforms

SFTPGo is developed and tested on Linux. After each commit, the code is automatically built and tested on Linux, macOS and Windows using a [GitHub Action](./.github/workflows/development.yml). The test cases are regularly manually executed and passed on FreeBSD. Other *BSD variants should work too.

## Requirements

- Go 1.14 or higher as build only dependency.
- A suitable SQL server to use as data provider: PostgreSQL 9.4+ or MySQL 5.6+ or SQLite 3.x.
- The SQL server is optional: you can choose to use an embedded bolt database as key/value store or an in memory data provider.

## Installation

Binary releases for Linux, macOS, and Windows are available. Please visit the [releases](https://github.com/drakkan/sftpgo/releases "releases") page.

An official Docker image is available. Documentation is [here](./docker/README.md).

Some Linux distro packages are available:

- For Arch Linux via AUR:
  - [sftpgo](https://aur.archlinux.org/packages/sftpgo/). This package follows stable releases. It requires `git`, `gcc` and `go` to build.
  - [sftpgo-bin](https://aur.archlinux.org/packages/sftpgo-bin/). This package follows stable releases downloading the prebuilt linux binary from GitHub. It does not require `git`, `gcc` and `go` to build.
  - [sftpgo-git](https://aur.archlinux.org/packages/sftpgo-git/). This package builds and installs the latest git master. It requires `git`, `gcc` and `go` to build.
- Deb and RPM packages are built after each commit and for each release.
- For Ubuntu a PPA is available [here](https://launchpad.net/~sftpgo/+archive/ubuntu/sftpgo).

You can easily test new features selecting a commit from the [Actions](https://github.com/drakkan/sftpgo/actions) page and downloading the matching build artifacts for Linux, macOS or Windows. GitHub stores artifacts for 90 days.

Alternately, you can [build from source](./docs/build-from-source.md).

## Configuration

A full explanation of all configuration methods can be found [here](./docs/full-configuration.md).

Please make sure to [initialize the data provider](#data-provider-initialization-and-management) before running the daemon!

To start SFTPGo with the default settings, simply run:

```bash
sftpgo serve
```

Check out [this documentation](./docs/service.md) if you want to run SFTPGo as a service.

### Data provider initialization and management

Before starting the SFTPGo server please ensure that the configured data provider is properly initialized/updated.

SQL based data providers (SQLite, MySQL, PostgreSQL) require the creation of a database containing the required tables. Memory and bolt data providers do not require an initialization but they could require an update to the existing data after upgrading SFTPGo.

For PostgreSQL and MySQL providers, you need to create the configured database.

SFTPGo will attempt to automatically detect if the data provider is initialized/updated and if not, will attempt to initialize/ update it on startup as needed.

Alternately, you can create/update the required data provider structures yourself using the `initprovider` command.

For example, you can simply execute the following command from the configuration directory:

```bash
sftpgo initprovider
```

Take a look at the CLI usage to learn how to specify a different configuration file:

```bash
sftpgo initprovider --help
```

You can disable automatic data provider checks/updates at startup by setting the `update_mode` configuration key to `1`.

If for some reason you want to downgrade SFTPGo, you may need to downgrade your data provider schema and data as well. You can use the `revertprovider` command for this task.

We support the follwing schema versions:

- `6`, this is the current git master
- `4`, this is the schema for v1.0.0-v1.2.x

So, if you plan to downgrade from git master to 1.2.x, you can prepare your data provider executing the following command from the configuration directory:

```shell
sftpgo revertprovider --to-version 4
```

Take a look at the CLI usage to learn how to specify a different configuration file:

```bash
sftpgo revertprovider --help
```

The `revertprovider` command is not supported for the memory provider.

## Users and folders management

After starting SFTPGo you can manage users and folders using:

- the [web based administration interface](./docs/web-admin.md)
- the [REST API](./docs/rest-api.md)
- the sample [REST API CLI](./examples/rest-api-cli)

To support embedded data providers like `bolt` and `SQLite` we can't have a CLI that directly write users and folders to the data provider, we always have to use the REST API.

## Tutorials

Some step-to-step tutorials can be found inside the source tree [howto](./docs/howto "How-to") directory.

## Authentication options

### External Authentication

Custom authentication methods can easily be added. SFTPGo supports external authentication modules, and writing a new backend can be as simple as a few lines of shell script. More information can be found [here](./docs/external-auth.md).

### Keyboard Interactive Authentication

Keyboard interactive authentication is, in general, a series of questions asked by the server with responses provided by the client.
This authentication method is typically used for multi-factor authentication.

More information can be found [here](./docs/keyboard-interactive.md).

## Dynamic user creation or modification

A user can be created or modified by an external program just before the login. More information about this can be found [here](./docs/dynamic-user-mod.md).

## Custom Actions

SFTPGo allows to configure custom commands and/or HTTP notifications on file upload, download, delete, rename, on SSH commands and on user add, update and delete.

More information about custom actions can be found [here](./docs/custom-actions.md).

## Virtual folders

Directories outside the user home directory can be exposed as virtual folders, more information [here](./docs/virtual-folders.md).

## Other hooks

You can get notified as soon as a new connection is established using the [Post-connect hook](./docs/post-connect-hook.md) and after each login using the [Post-login hook](./docs/post-login-hook.md).
You can use your own hook to [check passwords](./docs/check-password-hook.md).

## Storage backends

### S3 Compatible Object Storage backends

Each user can be mapped to the whole bucket or to a bucket virtual folder. This way, the mapped bucket/virtual folder is exposed over SFTP/SCP/FTP/WebDAV. More information about S3 integration can be found [here](./docs/s3.md).

### Google Cloud Storage backend

Each user can be mapped with a Google Cloud Storage bucket or a bucket virtual folder. This way, the mapped bucket/virtual folder is exposed over SFTP/SCP/FTP/WebDAV. More information about Google Cloud Storage integration can be found [here](./docs/google-cloud-storage.md).

### Azure Blob Storage backend

Each user can be mapped with an Azure Blob Storage container or a container virtual folder. This way, the mapped container/virtual folder is exposed over SFTP/SCP/FTP/WebDAV. More information about Azure Blob Storage integration can be found [here](./docs/azure-blob-storage.md).

### Other Storage backends

Adding new storage backends is quite easy:

- implement the [Fs interface](./vfs/vfs.go#L18 "interface for filesystem backends").
- update the user method `GetFilesystem` to return the new backend
- update the web interface and the REST API CLI
- add the flags for the new storage backed to the `portable` mode

Anyway, some backends require a pay per use account (or they offer free account for a limited time period only). To be able to add support for such backends or to review pull requests, please provide a test account. The test account must be available for enough time to be able to maintain the backend and do basic tests before each new release.

## Brute force protection

The [connection failed logs](./docs/logs.md) can be used for integration in tools such as [Fail2ban](http://www.fail2ban.org/). Example of [jails](./fail2ban/jails) and [filters](./fail2ban/filters) working with `systemd`/`journald` are available in fail2ban directory.

## Account's configuration properties

Details information about account configuration properties can be found [here](./docs/account.md).

## Performance

SFTPGo can easily saturate a Gigabit connection on low end hardware with no special configuration, this is generally enough for most use cases.

More in-depth analysis of performance can be found [here](./docs/performance.md).

## Release Cadence

SFTPGo releases are feature-driven, we don't have a fixed time based schedule. As a rough estimate, you can expect 1 or 2 new releases per year.

## Acknowledgements

SFTPGo makes use of the third party libraries listed inside [go.mod](./go.mod).
Some code was initially taken from [Pterodactyl SFTP Server](https://github.com/pterodactyl/sftp-server).
We are very grateful to all the people who contributed with ideas and/or pull requests.

## License

GNU GPLv3
