# Post-login hook

This hook is executed after a login or after closing a connection for authentication timeout. Defining an appropriate `post_login_scope` you can get notifications for failed logins, successful logins or both.

Combining this hook with the [Post-connect hook](./post-connect-hook.md) you can implement your own (even for Protocol) blacklist/whitelist of IP addresses.

Please keep in mind that you can easily configure specialized program such as [Fail2ban](http://www.fail2ban.org/) for brute force protection. Executing a hook after each login can be heavy.

The `post-login-hook` can be defined as the absolute path of your program or an HTTP URL.

If the hook defines an external program it can reads the following environment variables:

- `SFTPGO_LOGIND_USER`, username, can be empty if the connection is closed for authentication timeout
- `SFTPGO_LOGIND_IP`
- `SFTPGO_LOGIND_METHOD`, possible values are `publickey`, `password`, `keyboard-interactive`, `publickey+password`, `publickey+keyboard-interactive` or `no_auth_tryed`
- `SFTPGO_LOGIND_STATUS`, 1 means login OK, 0 login KO
- `SFTPGO_LOGIND_PROTOCOL`, possible values are `SSH`, `FTP`, `DAV`

Previous global environment variables aren't cleared when the script is called.
The program must finish within 20 seconds.

If the hook is an HTTP URL then it will be invoked as HTTP POST. The request body will contain a JSON serialized struct with the following fields:

- `username`
- `login_method`
- `ip`
- `protocol`
- `status`

The HTTP request will use the global configuration for HTTP clients.

The `post_login_scope` supports the following configuration values:

- `0` means notify both failed and successful logins
- `1` means notify failed logins. Connections closed for authentication timeout are notified as failed connections. You will get an empty username in this case
- `2` means notify successful logins
