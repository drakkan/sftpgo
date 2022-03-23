# Plugin system

SFTPGo's plugins are completely separate, standalone applications that SFTPGo executes and communicates with over RPC. This means the plugin process does not share the same memory space as SFTPGo and therefore can only access the interfaces and arguments given to it. This also means a crash in a plugin can not crash the entirety of SFTPGo.

## Configuration

The plugins are configured via the `plugins` section in the main SFTPGo configuration file. You basically have to set the path to your plugin, the plugin type and any plugin specific configuration parameters. If you set the SHA256 checksum for the plugin executable, SFTPGo will verify the plugin integrity before starting it.

For added security you can enable the automatic TLS. In this way, the client and the server automatically negotiate mutual TLS for transport authentication. This ensures that only the original client will be allowed to connect to the server, and all other connections will be rejected. The client will also refuse to connect to any server that isn't the original instance started by the client.

The following plugin types are supported:

- `auth`, allows to authenticate users.
- `notifier`, allows to receive notifications for supported filesystem events such as file uploads, downloads etc. and provider events such as objects add, update, delete.
- `kms`, allows to support additional KMS providers.
- `metadata`, allows to store metadata, such as the last modification time, for storage backends that does not support them (S3, Google Cloud Storage, Azure Blob).
- `ipfilter`, allows to allow/deny access based on client IP.

Full configuration details can be found [here](./full-configuration.md).

:warning: Please note that the plugin system is experimental, the exposed configuration parameters and interfaces may change in a backward incompatible way in future.

## Available plugins

Some "official" supported plugins can be found [here](https://github.com/sftpgo/).

## Plugin Development

:warning: Advanced topic! Plugin development is a highly advanced topic in SFTPGo, and is not required knowledge for day-to-day usage. If you don't plan on writing any plugins, we recommend not reading this section of the documentation.

Because SFTPGo communicates to plugins over a RPC interface, you can build and distribute a plugin for SFTPGo without having to rebuild SFTPGo itself.

In theory, because the plugin interface is HTTP, you could even develop a plugin using a completely different programming language! (Disclaimer, you would also have to re-implement the plugin API which is not a trivial amount of work).

Developing a plugin is simple. The only knowledge necessary to write a plugin is basic command-line skills and basic knowledge of the [Go programming language](http://golang.org/).

Your plugin implementation needs to satisfy the interface for the plugin type you want to build. You can find these definitions in the [docs](https://pkg.go.dev/github.com/sftpgo/sdk/plugin#section-directories).

The SFTPGo plugin system uses the HashiCorp [go-plugin](https://github.com/hashicorp/go-plugin) library. Please refer to its documentation for more in-depth information on writing plugins.
