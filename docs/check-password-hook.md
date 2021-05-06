# Check password hook

This hook allows you to externally check the provided password, its main use case is to allow to easily support things like password+OTP for protocols without keyboard interactive support such as FTP and WebDAV. You can ask your users to login using a string consisting of a fixed password and a One Time Token, you can verify the token inside the hook and ask to SFTPGo to verify the fixed part.

The same thing can be achieved using [External authentication](./external-auth.md) but using this hook is simpler in some use cases.

The `check password hook` can be defined as the absolute path of your program or an HTTP URL.

The expected response is a JSON serialized struct containing the following keys:

- `status` integer. 0 means KO, 1 means OK, 2 means partial success
- `to_verify` string. For `status` = 2 SFTPGo will check this password against the one stored inside SFTPGo data provider

If the hook defines an external program it can read the following environment variables:

- `SFTPGO_AUTHD_USERNAME`
- `SFTPGO_AUTHD_PASSWORD`
- `SFTPGO_AUTHD_IP`
- `SFTPGO_AUTHD_PROTOCOL`, possible values are `SSH`, `FTP`, `DAV`, `HTTP`

Previous global environment variables aren't cleared when the script is called. The content of these variables is _not_ quoted. They may contain special characters. They are under the control of a possibly malicious remote user.

The program must write, on its standard output, the expected JSON serialized response described above.

If the hook is an HTTP URL then it will be invoked as HTTP POST. The request body will contain a JSON serialized struct with the following fields:

- `username`
- `password`
- `ip`
- `protocol`, possible values are `SSH`, `FTP`, `DAV`

If authentication succeeds the HTTP response code must be 200 and the response body must contain the expected JSON serialized response described above.

The program hook must finish within 30 seconds, the HTTP hook timeout will use the global configuration for HTTP clients.

You can also restrict the hook scope using the `check_password_scope` configuration key:

- `0` means all supported protocols.
- `1` means SSH only
- `2` means FTP only
- `4` means WebDAV only

You can combine the scopes. For example, 6 means FTP and WebDAV.

You can disable the hook on a per-user basis.

An example check password program allowing 2FA using password + one time token can be found inside the source tree [checkpwd](../examples/OTP/authy/checkpwd) directory.
