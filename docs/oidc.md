# OpenID Connect

OpenID Connect integration allows you to map your identity provider users to SFTPGo admins/users and so you can login to SFTPGo Web Client and Web Admin user interfaces using your identity provider.

SFTPGo allows to configure per-binding OpenID Connect configurations. The supported configuration parameters are documented within the `oidc` section [here](./full-configuration.md).

Let's see a basic integration with the [Keycloak](https://www.keycloak.org/) identify provider. Other OpenID connect compatible providers should work by configuring them in a similar way.

We'll not go through the complete process of creating a realm/clients/users in Keycloak. You can look this up [here](https://www.keycloak.org/docs/latest/server_admin/index.html#admin-console).

Here is just an outline:

- create a realm named `sftpgo`
- in "Realm Settings" -> "Login" adjust the "Require SSL" setting as per your requirements
- create a client named `sftpgo-client`
- for the `sftpgo-client` set the `Access Type` to `confidential` and a valid redirect URI, for example if your SFTPGo instance is running on `http://192.168.1.50:8080` a valid redirect URI is `http://192.168.1.50:8080/*`
- for the `sftpgo-client`, in the `Mappers` settings, make sure that the username and the sftpgo role are added to the ID token. For example you can add the user attribute `sftpgo_role` as JSON string to the ID token and the `username` as `preferred_username` JSON string to the ID token
- for your users who need to be mapped as SFTPGo administrators add a custom attribute specifying `sftpgo_role` as key and `admin` as value

The resulting JSON configuration for the `sftpgo-client` that you can obtain from the "Installation" tab is something like this:

```json
{
  "realm": "sftpgo",
  "auth-server-url": "http://192.168.1.12:8086/auth/",
  "ssl-required": "none",
  "resource": "sftpgo-client",
  "credentials": {
    "secret": "jRsmE0SWnuZjP7djBqNq0mrf8QN77j2c"
  },
  "confidential-port": 0
}
```

Add the following configuration parameters to the SFTPGo configuration file (or use env vars to set them):

```json
...
    "oidc": {
      "client_id": "sftpgo-client",
      "client_secret": "jRsmE0SWnuZjP7djBqNq0mrf8QN77j2c",
      "config_url": "http://192.168.1.12:8086/auth/realms/sftpgo",
      "redirect_base_url": "http://192.168.1.50:8080",
      "username_field": "preferred_username",
      "role_field": "sftpgo_role"
    }
...
```

From SFTPGo login page click `Login with OpenID` button, you will be redirected to the Keycloak login page, after a successful authentication Keyclock will redirect back to SFTPGo Web Admin or SFTPGo Web Client.

Please note that the ID token returned from Keycloak must contain the `username_field` specified in the SFTPGo configuration and optionally the `role_field`. The mapped usernames must exist in SFTPGo.

Here is an example ID token which allows the SFTPGo admin `root` to access to the Web Admin UI.

```json
{
    "exp": 1644758026,
    "iat": 1644757726,
    "auth_time": 1644757647,
    "jti": "c6cf172d-08d6-41cf-8e5d-20b7ac0b8011",
    "iss": "http://192.168.1.12:8086/auth/realms/sftpgo",
    "aud": "sftpgo-client",
    "sub": "48b0de4b-3090-4315-bbcb-be63c48be1d2",
    "typ": "ID",
    "azp": "sftpgo-client",
    "nonce": "XLxfYDhMmWwiYctgLTCZjC",
    "session_state": "e20ab97c-d3a9-4e53-872d-09d104cbd286",
    "at_hash": "UwubF1W8H0XItHU_DIpjfQ",
    "acr": "0",
    "sid": "e20ab97c-d3a9-4e53-872d-09d104cbd286",
    "email_verified": false,
    "preferred_username": "root",
    "sftpgo_role": "admin"
}
```

And the following is an example ID token which allows the SFTPGo user `user1` to access to the Web Client UI.

```json
{
    "exp": 1644758183,
    "iat": 1644757883,
    "auth_time": 1644757647,
    "jti": "939de932-f941-4b04-90fc-7071b7cc6b10",
    "iss": "http://192.168.1.12:8086/auth/realms/sftpgo",
    "aud": "sftpgo-client",
    "sub": "48b0de4b-3090-4315-bbcb-be63c48be1d2",
    "typ": "ID",
    "azp": "sftpgo-client",
    "nonce": "wxcWPPi3H7ktembUdeToqQ",
    "session_state": "e20ab97c-d3a9-4e53-872d-09d104cbd286",
    "at_hash": "RSDpwzVG_6G2haaNF0jsJQ",
    "acr": "0",
    "sid": "e20ab97c-d3a9-4e53-872d-09d104cbd286",
    "email_verified": false,
    "preferred_username": "user1"
}
```

SFTPGo users (not admins) can be created/updated after successful OpenID authentication by defining a [pre-login hook](./dynamic-user-mod.md).
