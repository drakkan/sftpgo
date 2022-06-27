# SFTPGo

[![CI Status](https://github.com/drakkan/sftpgo/workflows/CI/badge.svg?branch=main&event=push)](https://github.com/drakkan/sftpgo/workflows/CI/badge.svg?branch=main&event=push)
[![Code Coverage](https://codecov.io/gh/drakkan/sftpgo/branch/main/graph/badge.svg)](https://codecov.io/gh/drakkan/sftpgo/branch/main)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docker Pulls](https://img.shields.io/docker/pulls/drakkan/sftpgo)](https://hub.docker.com/r/drakkan/sftpgo)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

[English](./README.md) | [简体中文](./README.zh_CN.md)

功能齐全、高度可配置化、支持自定义 HTTP/S，FTP/S 和 WebDAV 的 SFTP 服务。
一些存储后端支持：本地文件系统、加密本地文件系统、S3（兼容）对象存储，Google Cloud 存储，Azure Blob 存储，SFTP。

## 特性

- 支持服务本地文件系统、加密本地文件系统、S3 兼容对象存储、Google Cloud 存储、Azure Blob 存储或其它基于 SFTP/SCP/FTP/WebDAV 协议的 SFTP 账户。
- 虚拟目录支持：一个虚拟目录可以用于支持的存储后端。你可以，比如，一个 S3 用户暴露了一个 GCS bucket（或者其中一部分）在特定的路径下、一个加密本地文件系统在另一个。虚拟目录可以对于大量用户作为私密或者共享，分享虚拟目录你可以为每个用户定义不同的配额。
- 可配置的 [自定义命令 和/或 HTTP 钩子](./docs/custom-actions.md) 在 SSH 命令的 upload, pre-upload, download, pre-download, delete, pre-delete, rename, mkdir, rmdir 阶段，和用户添加、更新、删除阶段。
- 存储在 “数据提供程序” 中的虚拟账户。
- 支持 SQLite, MySQL, PostgreSQL, CockroachDB, Bolt (Go 原生键/值存储) 和内存数据提供程序。
- 为本地账户提供 Chroot 隔离。云端账户可以限制为特定的基本路径。
- 每个用户和每个目录虚拟权限，对于每个暴露的路径你可以允许或禁止：目录展示、上传、覆盖、下载、删除、重命名、创建文件夹、创建软连接、修改 owner/group/file 模式和更改时间。
- 为用户和目录管理提供、数据保留、备份、恢复和即时活动连接的实时报告，可能会强制关闭连接，提供 [REST API](./docs/rest-api.md)。
- [基于 Web 的管理员界面](./docs/web-admin.md) 可以容易地管理用户、目录和连接。
- [Web 客户端界面](./docs/web-client.md) 以便终端用户可以在浏览器中更改他们的凭据、管理和共享他们的文件。
- 公钥和密码认证。支持每个用户多个公钥。
- SSH 用户 [证书认证](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.8).
- 键盘交互认证。您可以轻松设置可定制的多因素身份认证。
- 部分验证。你可以配置多步验证请求，例如，用户密码在公钥验证之后。
- 每个用户的身份验证方法。
- [双重验证](./docs/howto/two-factor-authentication.md) 基于实现一次性密码 (RFC 6238) 可以与 Authy、Google Authenticator 和其他兼容的应用程序配合使用。
- 通过 [群组](./docs/groups.md) 精简用户管理。
- 通过外部 程序/HTTP API 自定义验证。
- Web 客户端和 Web 管理员他用户界面支持 [OpenID Connect](https://openid.net/connect/) 验证，所以它们很容易被集成在诸如 [Keycloak](https://www.keycloak.org/) 之类的身份认证程序。你可以在 [此](./docs/oidc.md) 获取更多信息。
- [静态数据加密](./docs/dare.md)。
- 在登录之前通过 程序/HTTP API 进行动态用户修改。
- 配额支持：账户拥有独立的磁盘配额表示为总计最大体积 和/或 最大文件数量。
- 带宽节流，基于客户端 IP 地址独立设置上传、下载和覆盖。
- 数据传输带宽限制，限制总量或基于客户端 IP 地址设置上传、下载和覆盖。限制可以通过 REST API 重置。
- 支持每个协议[限速](./docs/rate-limiting.md)，可以可选与内置的防护连接实现自动封禁重复超过设置限制的主机。
- 每个用户的最大并发会话。
- 每个用户和全局 IP 过滤：登录可以被限制在特定的 IP 段和指定的 IP 地址。
- 每个用户和每个文件夹类似于 shell 的模式过滤：文件可以被允许、禁止和隐藏基于类 shell 模式。
- 自动使 idle 连接终止。
- 通过内置的 [防护](./docs/defender.md) 自动管理禁止名单。
- 通过 [插件](https://github.com/sftpgo/sftpgo-plugin-geoipfilter) 实现 地理-IP 过滤。
- 原子上传是可配置的。
- 每个用户 文件/目录 所有权映射：你可以将所有用户映射到运行 SFEPGo 的系统账户（所有的平台都是支持的），或者你可以使用 root 用户运行 SFTPGo 并且映射每个用户或用户组到一个不同系统账户（仅支持 \*NIX）。
- 通过 SSH 支持 Git 仓库。
- 支持 SCP 和 rsync。
- 支持 FTP/S。你可以配置 FTP 服务为控制和数据连接都需要 TLS。
- [WebDAV](./docs/webdav.md) 是支持的。
- 两步 TLS 验证，具有客户端证书身份验证的 aka TLS，支持 REST API/Web Admin、FTPS 和 基于 HTTPS 的 WebDAV。
- 每个用户协议限制。你可以为每个用户配置允许的协议(SSH/HTTP/FTP/WebDAV)。
- 暴露 [输出指标](./docs/metrics.md)。
- 支持 HAProxy PROXY 协议：你可以不需要丢失客户端地址信息代理 和/或 负载平衡 SFTP/SCP/FTP 服务。
- 简单从 Linux 系统用户账户进行 [迁移](./examples/convertusers)。
- [可携带模式](./docs/portable-mode.md)：按需共享单个目录的便捷方式。
- [SFTP 子系统模式](./docs/sftp-subsystem.md)：你可以使用 SFTPGo 作为 OpenSSH 的 SFTP 子系统。
- 性能分析基于内置的 [分析器](./docs/profiling.md)。
- 配置项格式基于你的选择：JSON, TOML, YAML, HCL, envfile 都是支持的。
- 日志文件是精确的，它们被存储为易被解析的 JSON 格式。（[更多信息](./docs/logs.md)）
- SFTPGo 支持 [插件系统](./docs/plugins.md)，因此可以使用外部插件拓展。

## 平台

SFTPGo 基于 Linux 开发和创建。在每一次提交之后，代码会自动通过 [GitHub Actions](./.github/workflows/development.yml) 在 Linux、macOS 和 Windows 构建和测试。测试用例定期手动在 FreeBSD 执行，其他的 *BSD 变体同样适用。

## 要求

- Go 作为构建仅有的依赖。我们支持 [持续集成工作流](./.github/workflows) 中使用的 Go 版本。
- 使用适配的 SQL 服务作为数据提供程序：PostgreSQL 9.4+, MySQL 5.6+, SQLite 3.x, CockroachDB stable.
- SQL 服务是可选的：你可以使用一个内置的 bolt 数据库以 键/值 存储，或者一个内存中的数据提供程序。

## 安装

为 Linux、macOS 和 Windows 提供的二进制发行版是可用的。请参考 [发行版](https://github.com/drakkan/sftpgo/releases "releases") 页面。

一个官方的 Docker 镜像是可用的。文档参考 [Docker](./docker/README.md)。

<details>

<summary>一些 Linux 分支包是可用的</summary>

- Arch Linux 通过 AUR:
  - [sftpgo](https://aur.archlinux.org/packages/sftpgo/)。这个包跟随稳定的发行版。需要 `git`、`gcc` 和 `go` 进行构建。
  - [sftpgo-bin](https://aur.archlinux.org/packages/sftpgo-bin/)。这个包跟随稳定的发行版从 GitHub 下载预构建 Linux 二进制文件。不需要 `git`、`gcc` 和 `go` 进行构建。
  - [sftpgo-git](https://aur.archlinux.org/packages/sftpgo-git/)。这个包构建和下载基于最新的 `git` 主分支。需要 `git`、`gcc` 和 `go` 进行构建。
- Deb and RPM 包在每次提交和发行之后构建。
- Ubuntu PPA 在 [此](https://launchpad.net/~sftpgo/+archive/ubuntu/sftpgo) 可用。
- Void Linux 提供一个 [官方包](https://github.com/void-linux/void-packages/tree/master/srcpkgs/sftpgo)。

</details>

SFTPGo 在 [AWS Marketplace](https://aws.amazon.com/marketplace/seller-profile?id=6e849ab8-70a6-47de-9a43-13c3fa849335) 和 [Azure Marketplace](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/prasselsrl1645470739547.sftpgo_linux) 同样可用，在此付费可以帮助 SFTPGo 成为一个可持续发展的长期项目。

<details><summary>Windows 包</summary>

- Windows installer 安装和运行 SFTPGo 作为一个 Windows 服务。
- 开箱即用的包启动按需使用的 SFTPGo。
- [winget](https://docs.microsoft.com/en-us/windows/package-manager/winget/install) 包下载和运行 SFTPGo 作为一个 Windows 服务：`winget install SFTPGo`。
- [Chocolatey 包](https://community.chocolatey.org/packages/sftpgo) 下载和运行 SFTPGo 作为一个 Windows 服务。

</details>

在 FreeBSD，你可以从 [SFTPGo port](https://www.freshports.org/ftp/sftpgo) 下载。
在 DragonFlyBSD，你可以从 [DPorts](https://github.com/DragonFlyBSD/DPorts/tree/master/ftp/sftpgo) 下载。
您可以从 [Actions](https://github.com/drakkan/sftpgo/Actions) 页面选择一个 commit 并下载 Linux、macOS 或 Windows 的匹配构建，从而轻松测试新特性。GitHub 存储 90 天。

另外，你可以 [从源码构建](./docs/build-from-source.md)。

[不耐烦的快速上手指南](./docs/howto/getting-started.md).

## 配置项

可以完整的配置项方法说明可以参考 [配置项](./docs/full-configuration.md)。

请确保按需运行之前，[初始化数据提供程序](#data-provider-initialization-and-management)。

默认配置启动 STFPGo，运行：

```bash
sftpgo serve
```

如果你将 SFTPGo作为服务，请参阅 [这篇文档](./docs/service.md)。

### 数据提供程序初始化和管理

在启动 SFTPGo 服务之前，请确保配置的数据提供程序已经被适当的 初始化/更新。

对于 PostgreSQL, MySQL 和 CockroachDB 提供，你需要创建一个配置数据库。对于 SQLite，配置数据库将会在启动时被自动创建。内存和 bolt 数据提供程序不需要初始化，但是它们需要在升级 SFTPGo 之后更新现有的数据。

SFTPGo 会尝试自动探测数据提供程序是否被 初始化/更新；如果没有，将会在启动时尝试 初始化/更新。

或者，你可以通过 `initprovider` 命令自行 创建/更新 需要的数据提供程序结构。

比如，你可以执行在配置文件目录下面的命令：

```bash
sftpgo initprovider
```

看一看 CLI 用法学习如何指定一个不同的配置文件：

```bash
sftpgo initprovider --help
```

你可以在启动阶段通过设置 `update_mode` 配置项为 `1`，禁止自动数据提供程序 检查/更新。

你可以通过使用 `resetprovider` 子命令重置你的数据提供程序。看一看 CLI 用法获取更多细节信息：

```bash
sftpgo resetprovider --help
```

:warning: 请注意一些数据提供程序（比如 MySQL 和 CockroachDB）不支持事务内的方案更改，这意味着如果迁移被强制中止或由多个实例同时运行，您可能会得到不一致的方案。

## 创建第一个管理员

开始使用 SFTPGo，你需要创建一个管理员用户，你可以通过不同的方式进行实现：

- 通过 web 管理员界面。默认 URL 是 [http://127.0.0.1:8080/web/admin](http://127.0.0.1:8080/web/admin)
- 通过加载初始数据
- 通过在你的配置文件启用 `create_default_admin` 并设置环境变量 `SFTPGO_DEFAULT_ADMIN_USERNAME` 和 `SFTPGO_DEFAULT_ADMIN_PASSWORD`

## 升级

SFTPGo 支持从之前的发行版分支升级到当前分支。
一些支持的升级路径如下：

- 从 1.2.x 到 2.0.x
- 从 2.0.x 到 2.1.x 等。

对支持的升级路径，数据和方案将会自动迁移，你可以使用 `initprovider` 命令作为替代。

所以，比如，你想从 1.2.x 之前的版本升级到 2.0.x，你必须首先安装 1.2.x 版本，升级数据提供程序并最终安装版本 2.0.x。建议安装最新的可用小版本，如果 1.2.2 可用就不要安装 1.2.0 版本。

从以前发行版分支到当前版本，都支持从独立于数据提供程序的 JSON 转储中加载数据。升级 SFTPGo 后，建议从新版本重新生成 JSON 转储。

## 降级

如果因为一些原因你想降级 SFTPGo，你可能需要降级你的用户数据提供程序方案和数据。你可以使用 `revertprovider` 命令执行这项任务。

对于升级，SFTPGo 支持从先前的发行版分支降级到当前分支。

所以，如果你有计划从 2.0.x 降级到 1.2.x，之前先卸载 2.0.x 版本，你可以通过从配置目录执行以下命令来准备你的数据提供程序：

```shell
sftpgo revertprovider --to-version 4
```

看一看 CLI 的用法、了解 `--to-version` 参数支持的参数，了解如何去指定一个不同的配置文件：

```shell
sftpgo revertprovider --help
```

`revertprovider` 命令不支持内存数据提供程序。

请注意我们只支持当前发行版分支和当前主分支，如果你发现了个 bug，最好是报告这个问题而不是降级到一个老的、不被支持的版本。

## 用户和目录管理

在启动 SFTPGo 之后，你可以管理用户和目录使用：

- [基于 Web 的管理员界面](./docs/web-admin.md)
- [REST API](./docs/rest-api.md)

支持内置的数据提供程序比如 `bolt` 和 `SQLite`。我们不能使用 CLI 直接将用户和文件夹写到数据提供程序，通常使用 REAST API。

对于用户、目录、管理员和其它资源的细节，都记录在 [OpenAPI](./openapi/openapi.yaml) 方案。如果你想在不手动引入的情况下渲染方案，你可以在 [Stoplight](https://sftpgo.stoplight.io/docs/sftpgo/openapi.yaml) 上暴露它。

## 教程

一些手把手教程可以在源码文件树中的 [howto](./docs/howto "How-to") 目录找到。

## 认证选项

<details><summary>外部认证</summary>

自定义认证方法可以很容易被添加。SFTPGo 支持外部认证模块，编写一个后端可以如编写几行 shell 脚本那样简单。更多的信息可以参考 [外部认证](./docs/external-auth.md)。

</details>

<details><summary>键盘交互认证</summary>

一般来说，键盘交互身份验证是服务器提出的一系列问题，由客户端提供响应。

这种身份认证方法通常用于多因素身份认证。

更多信息参考 [键盘交互](./docs/keyboard-interactive.md)。

</details>

## 动态用户创建或修改

一个用户可以通过外部程序在登录之前被创建和修改。更多关于此可以参考 [动态用户修改](./docs/dynamic-user-mod.md)。

## 自定义动作

SFTPGo 允许你配置自定义的命令 和/或 HTTP 钩子去获取关于文件上传、删除和一些其它操作的通知。

更多关于自定义动作的信息你可以参考 [自定义动作](./docs/custom-actions.md)。

## 虚拟目录

用户 home 文件夹外或者基于不同存储提供的目录，可以作为虚拟目录进行暴露，详细信息参考 [虚拟目录](./docs/virtual-folders.md)。

## 其它钩子

你可以使用 [Post-connect 钩子](./docs/post-connect-hook.md) 及时获取新的连接建立，使用 [Post-login hook](./docs/post-login-hook.md) 获取每次登录之后的通知。你可以使用你自己的钩子去 [验证密码](./docs/check-password-hook.md)。

## 存储后端

### S3/GCP/Azure

每个用户可以被映射到 [S3 兼容对象存储](./docs/s3.md) /[Google Cloud 存储](./docs/google-cloud-storage.md)/[Azure Blob 存储](./docs/azure-blob-storage.md) bucket 或者一个 bucket 虚拟目录，通过 SFTP/SCP/FTP/WebDAV 进行暴露。

### SFTP 后端

每个用户可以被映射到另一个 SFTP 服务器账户或者它的子目录。更多的信息可以参考 [sftpfs](./docs/sftpfs.md)。

### 加密后端

数据静态加密通过 [cryptfs 后端](./docs/dare.md) 进行支持。

### 其它存储后端

添加新的存储后端非常简单：

- 实现 [Fs 接口](./vfs/vfs.go#L28 "interface for filesystem backends")
- 更新用户方法 `GetFilesystem` 返回新的后端
- 更新 web 接口和 REST API CLI
- 为新的存储后端添加向 `portable` 模式添加 flags

无论如何，一些后端需要按次付费账户（或者他们提供限制期限内提供免费账户）。为了能够添加这些账户支持或者预览 PRs，请提供一个测试账户。测试账户必须在提供足够长时间维护此后端，并且支持每一次新的发行版之前做基本测试。

## 强力保护

SFTPGo 支持内置 [防护](./docs/defender.md)。

你可以使用 [连接失败日志](./docs/logs.md) 在诸如 [Fail2ban](http://www.fail2ban.org/) 进行工具内集成。[jails](./fail2ban/jails) 和 [filters](./fail2ban/filters) 示例，在 fail2ban 目录中与 `systemd`/`journald` 是可以同时工作的。

## 账户配置属性

关于账户配置属性的细节信息，请参考 [账户](./docs/account.md)。

## 性能

SFTPGo 在没有特殊配置的情况下，可以实现低端硬件轻松达到 GB 量级连接，对于大多数场景足够使用了。

更多深度性能分析可以参考 [性能](./docs/performance.md)。

## 发行节奏

STFPGo 发行版是特性驱动的，我们没有基于计划的固定时间。粗略估计，你可以每年期待一到两个新的发行版。

## 感谢

SFTPGo 使用了 [go.mod](./go.mod) 中列出的第三方库。

我们非常感激所有贡献想法 和/或 PRs。

感谢 [ysura](https://www.ysura.com/) 给予我测试 AWS S3 账户的稳定权限。

## 赞助者

我希望可以使 STFPGo 成为一个可持续发展的长期项目，你的 [赞助](https://github.com/sponsors/drakkan) 对我很有帮助！:heart:

感谢我们的赞助者！

[<img src="https://www.7digital.com/wp-content/themes/sevendigital/images/top_logo.png" alt="7digital logo">](https://www.7digital.com/)

## 许可证

GNU AGPL-3.0-only
