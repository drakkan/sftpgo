# External Authentication

To enable external authentication, you must set the absolute path of your authentication program or an HTTP URL using the `external_auth_hook` key in your configuration file.

The external program can read the following environment variables to get info about the user trying to authenticate:

- `SFTPGO_AUTHD_USERNAME`
- `SFTPGO_AUTHD_USER`, STPGo user serialized as JSON, empty if the user does not exist within the data provider
- `SFTPGO_AUTHD_IP`
- `SFTPGO_AUTHD_PROTOCOL`, possible values are `SSH`, `FTP`, `DAV`, `HTTP`
- `SFTPGO_AUTHD_PASSWORD`, not empty for password authentication
- `SFTPGO_AUTHD_PUBLIC_KEY`, not empty for public key authentication
- `SFTPGO_AUTHD_KEYBOARD_INTERACTIVE`, not empty for keyboard interactive authentication
- `SFTPGO_AUTHD_TLS_CERT`, TLS client certificate PEM encoded. Not empty for TLS certificate authentication

Previous global environment variables aren't cleared when the script is called. The content of these variables is _not_ quoted. They may contain special characters. They are under the control of a possibly malicious remote user.
The program can inspect the SFTPGo user, if it exists, using the `SFTPGO_AUTHD_USER` environment variable.
The program must write, on its standard output:

- a valid SFTPGo user serialized as JSON if the authentication succeeds. The user will be added/updated within the defined data provider
- an empty string, or no response at all, if authentication succeeds and the existing SFTPGo user does not need to be updated. Please note that in versions 2.0.x and earlier an empty response was interpreted as an authentication error
- a user with an empty username if the authentication fails

If the hook is an HTTP URL then it will be invoked as HTTP POST. The request body will contain a JSON serialized struct with the following fields:

- `username`
- `ip`
- `user`, STPGo user serialized as JSON, omitted if the user does not exist within the data provider
- `protocol`, possible values are `SSH`, `FTP`, `DAV`, `HTTP`
- `password`, not empty for password authentication
- `public_key`, not empty for public key authentication
- `keyboard_interactive`, not empty for keyboard interactive authentication
- `tls_cert`, TLS client certificate PEM encoded. Not empty for TLS certificate authentication

If authentication succeeds the HTTP response code must be 200 and the response body can be:

- a valid SFTPGo user serialized as JSON. The user will be added/updated within the defined data provider
- empty, the existing SFTPGo user does not need to be updated. Please note that in versions 2.0.x and earlier an empty response was interpreted as an authentication error

If the authentication fails the HTTP response code must be != 200 or the returned SFTPGo user must have an empty username.

If the hook returns a user who is only allowed to authenticate using public key + password (multi step authentication), your hook will be invoked for each authentication step, so it must validate the public key and password separately. SFTPGo will take care that the client uses the allowed sequence.

Actions defined for users added/updated will not be executed in this case and an already logged in user with the same username will not be disconnected.

The program hook must finish within 30 seconds, the HTTP hook timeout will use the global configuration for HTTP clients.

This method is slower than built-in authentication, but it's very flexible as anyone can easily write his own authentication hooks.
You can also restrict the authentication scope for the hook using the `external_auth_scope` configuration key:

- `0` means all supported authentication scopes. The external hook will be used for password, public key, keyboard interactive and TLS certificate authentication
- `1` means passwords only
- `2` means public keys only
- `4` means keyboard interactive only
- `8` means TLS certificate only

You can combine the scopes. For example, 3 means password and public key, 5 means password and keyboard interactive, and so on.

Let's see a very basic example. Our sample authentication program will only accept user `test_user` with any password or public key.

```shell
#!/bin/sh

if test "$SFTPGO_AUTHD_USERNAME" = "test_user"; then
  echo '{"status":1,"username":"test_user","expiration_date":0,"home_dir":"/tmp/test_user","uid":0,"gid":0,"max_sessions":0,"quota_size":0,"quota_files":100000,"permissions":{"/":["*"],"/somedir":["list","download"]},"upload_bandwidth":0,"download_bandwidth":0,"filters":{"allowed_ip":[],"denied_ip":[]},"public_keys":[]}'
else
  echo '{"username":""}'
fi
```

The structure for SFTPGo users can be found within the [OpenAPI schema](../openapi/openapi.yaml).

You can instruct SFTPGo to cache the external user by setting an `external_auth_cache_time` in user object returned by your hook. The `external_auth_cache_time` defines the cache time in seconds.

You can disable the hook on a per-user basis so that you can mix external and internal users.

An example authentication program allowing to authenticate against an LDAP server can be found inside the source tree [ldapauth](../examples/ldapauth) directory.

An example server, to use as HTTP authentication hook, allowing to authenticate against an LDAP server can be found inside the source tree [ldapauthserver](../examples/ldapauthserver) directory.

If you have an external authentication hook that could be useful to others too, please let us know and/or please send a pull request.
