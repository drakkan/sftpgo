# Post-disconnect hook

This hook is executed as soon as a SSH/FTP connection is closed. SSH is a multiplexing protocol, a client can open multiple channels on a single connection or can disconnect without opening any channels. For SSH-based connections (SFTP/SCP/SSH commands), SFTPGo notifies the disconnection of the channel so there is no exact match with the post-connect hook.

The hook is not executed for stateless protocols such as HTTP and WebDAV.

The `post_disconnect_hook` can be defined as the absolute path of your program or an HTTP URL.

If the hook defines an external program it can read the following environment variables:

- `SFTPGO_CONNECTION_IP`
- `SFTPGO_CONNECTION_PROTOCOL`, possible values are `SSH`, `FTP`, `DAV`, `HTTP`, `OIDC` (OpenID Connect)
- `SFTPGO_CONNECTION_USERNAME`, can be empty if the channel is closed before user authentication
- `SFTPGO_CONNECTION_DURATION`, connection duration in milliseconds

Previous global environment variables aren't cleared when the script is called.
The program must finish within 20 seconds.

If the hook defines an HTTP URL then this URL will be invoked as HTTP GET with the following query parameters:

- `ip`
- `protocol`, possible values are `SSH`, `FTP`, `DAV`, `HTTP`, `OIDC` (OpenID Connect)
- `username`, can be empty if the channel is closed before user authentication
- `connection_duration`, connection duration in milliseconds

The HTTP hook will use the global configuration for HTTP clients and will respect the retry configurations.
