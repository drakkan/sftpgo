# Post-connect hook

This hook is executed as soon as a new connection is established. It notifies the connection's IP address and protocol. Based on the received response, the connection is accepted or rejected. Combining this hook with the [Post-login hook](./post-login-hook.md) you can implement your own (even for Protocol) blacklist/whitelist of IP addresses.

The `post_connect_hook` can be defined as the absolute path of your program or an HTTP URL.

If the hook defines an external program it can read the following environment variables:

- `SFTPGO_CONNECTION_IP`
- `SFTPGO_CONNECTION_PROTOCOL`, possible values are `SSH`, `FTP`, `DAV`, `HTTP`, `OIDC` (OpenID Connect)

If the external command completes with a zero exit status the connection will be accepted otherwise rejected.

Global environment variables are cleared, for security reasons, when the script is called. You can set additional environment variables in the "command" configuration section.
The program must finish within 20 seconds.

If the hook defines an HTTP URL then this URL will be invoked as HTTP GET with the following query parameters:

- `ip`
- `protocol`, possible values are `SSH`, `FTP`, `DAV`, `HTTP`, `OIDC` (OpenID Connect)

The connection is accepted if the HTTP response code is `200` otherwise rejected.

The HTTP hook will use the global configuration for HTTP clients and will respect the retry configurations.
