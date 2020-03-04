# External Authentication

To enable external authentication, you must set the absolute path of your authentication program using `external_auth_program` key in your configuration file.

The external program can read the following environment variables to get info about the user trying to authenticate:

- `SFTPGO_AUTHD_USERNAME`
- `SFTPGO_AUTHD_PASSWORD`, not empty for password authentication
- `SFTPGO_AUTHD_PUBLIC_KEY`, not empty for public key authentication
- `SFTPGO_AUTHD_KEYBOARD_INTERACTIVE`, not empty for keyboard interactive authentication

Previous global environment variables aren't cleared when the script is called. The content of these variables is _not_ quoted. They may contain special characters. They are under the control of a possibly malicious remote user.
The program must write, on its standard output, a valid SFTPGo user serialized as JSON if the authentication succeed or an user with an empty username if the authentication fails.
If the authentication succeeds, the user will be automatically added/updated inside the defined data provider. Actions defined for users added/updated will not be executed in this case.
The external program should check authentication only. If there are login restrictions such as user disabled, expired, or login allowed only from specific IP addresses, it is enough to populate the matching user fields, and these conditions will be checked in the same way as for built-in users.
The external auth program should finish very quickly. It will be killed if it does not exit within 60 seconds.
This method is slower than built-in authentication, but it's very flexible as anyone can easily write his own authentication program.
You can also restrict the authentication scope for the external program using the `external_auth_scope` configuration key:

- 0 means all supported authetication scopes. The external program will be used for password, public key and keyboard interactive authentication
- 1 means passwords only
- 2 means public keys only
- 4 means keyboard interactive only

You can combine the scopes. For example, 3 means password and public key, 5 means password and keyboard interactive, and so on.

Let's see a very basic example. Our sample authentication program will only accept user `test_user` with any password or public key.

```
#!/bin/sh

if test "$SFTPGO_AUTHD_USERNAME" = "test_user"; then
  echo '{"status":1,"username":"test_user","expiration_date":0,"home_dir":"/tmp/test_user","uid":0,"gid":0,"max_sessions":0,"quota_size":0,"quota_files":100000,"permissions":{"/":["*"],"/somedir":["list","download"]},"upload_bandwidth":0,"download_bandwidth":0,"filters":{"allowed_ip":[],"denied_ip":[]},"public_keys":[]}'
else
  echo '{"username":""}'
fi
```

If you have an external authentication program that could be useful for others too, please let us know and/or send a pull request.
