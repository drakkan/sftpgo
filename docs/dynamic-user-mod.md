# Dynamic user creation or modification

Dynamic user creation or modification is supported via an external program or an HTTP URL that can be invoked just before the user login.
To enable dynamic user modification, you must set the absolute path of your program or an HTTP URL using the `pre_login_hook` key in your configuration file.

The external program can read the following environment variables to get info about the user trying to login:

- `SFTPGO_LOGIND_USER`, it contains the user trying to login serialized as JSON. A JSON serialized user id equal to zero means the user does not exist inside SFTPGo
- `SFTPGO_LOGIND_METHOD`, possible values are: `password`, `publickey`, `keyboard-interactive`, `TLSCertificate`, `IDP` (external identity provider)
- `SFTPGO_LOGIND_IP`, ip address of the user trying to login
- `SFTPGO_LOGIND_PROTOCOL`, possible values are `SSH`, `FTP`, `DAV`, `HTTP`, `OIDC` (OpenID Connect)

The program must write, on its standard output:

- an empty string (or no response at all) if the user should not be created/updated
- or the SFTPGo user, JSON serialized, if you want to create or update the given user

If the hook is an HTTP URL then it will be invoked as HTTP POST. The login method, the used protocol and the ip address of the user trying to login are added to the query string, for example `<http_url>?login_method=password&ip=1.2.3.4&protocol=SSH`.
The request body will contain the user trying to login serialized as JSON. If no modification is needed the HTTP response code must be 204, otherwise the response code must be 200 and the response body a valid SFTPGo user serialized as JSON.

Actions defined for user's updates will not be executed in this case and an already logged in user with the same username will not be disconnected, you have to handle these things yourself.

The JSON response can include only the fields to update instead of the full user. For example, if you want to disable the user, you can return a response like this:

```json
{"status": 0}
```

Please note that if you want to create a new user, the pre-login hook response must include all the mandatory user fields.

The program hook must finish within 30 seconds, the HTTP hook will use the global configuration for HTTP clients.

If an error happens while executing the hook then login will be denied.

"Dynamic user creation or modification" and "External Authentication" are mutually exclusive, they are quite similar, the difference is that "External Authentication" returns an already authenticated user while using "Dynamic users modification" you simply create or update a user. The authentication will be checked inside SFTPGo.
In other words while using "External Authentication" the external program receives the credentials of the user trying to login (for example the cleartext password) and it needs to validate them. While using "Dynamic users modification" the pre-login program receives the user stored inside the dataprovider (it includes the hashed password if any) and it can modify it, after the modification SFTPGo will check the credentials of the user trying to login.

For SFTPGo users (not admins) authenticating using an external identity provider such as OpenID Connect, the pre-login hook will be executed after a successful authentication against the external IDP so that you can create/update the SFTPGo user matching the one authenticated against the identity provider. This is the only case where the pre-login hook is executed even if an external authentication hook is defined.

You can disable the hook on a per-user basis.

Let's see a very basic example. Our sample program will grant access to the existing user `test_user` only in the time range 10:00-18:00. Other users will not be modified since the program will terminate with no output.

```shell
#!/bin/bash

CURRENT_TIME=`date +%H:%M`
if [[ "$SFTPGO_LOGIND_USER" =~ "\"test_user\"" ]]
then
  if [[ $CURRENT_TIME > "18:00" || $CURRENT_TIME < "10:00" ]]
  then
    echo '{"status":0}'
  else
    echo '{"status":1}'
  fi
fi
```

Please note that this is a demo program and it might not work in all cases. For example, the username should be obtained by parsing the JSON serialized user and not by searching the username inside the JSON as shown here.

The structure for SFTPGo users can be found within the [OpenAPI schema](../openapi/openapi.yaml).
