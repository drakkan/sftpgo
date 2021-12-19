# Two-factor Authentication (2FA)

Two-factor authentication (also known as 2FA) is a subset of multi-factor authentication. It allows SFTPGo users and admins to enable additional protection for their account by requiring a combination of two different authentication factors:

- something they know (e.g. their password)
- something they have (usually their smartphone).

2FA is an excellent way to improve your security profile and provide an added layer of protection to your data.

SFTPGo supports authenticator apps that use TOTP (time based one-time password). These include apps such as Authy, Google Authenticator and any other apps that support time-based one time passwords ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)).

## Preliminary Note

Before proceeding further you need a working SFTPGo installation.

## Configure SFTPGo

Two-factor authentication is enabled by default with the following settings.

```json
  "mfa": {
    "totp": [
      {
        "name": "Default",
        "issuer": "SFTPGo",
        "algo": "sha1"
      }
    ]
  },
```

The `issuer` and `algo` are exposed to the authenticators apps. For example, you could set your company/organization name as `issuer` and an `algo` appropriate for your target apps/devices. The supported algorithms are: `sha1`, `sha256`, `sha512`. Currently Google Authenticator app on iPhone seems to only support `sha1`, please check the compatibility with your target apps/device before setting a different algorithm.

You can also define multiple configurations, for example one that uses `sha256` or `sha512` and another one that uses `sha1` and instruct your users to use the appropriate configuration for their devices/apps. The algorithm should not be changed if there are users or admins using the configuration. The `name` is exposed to the users/admins when they select the 2FA configuration to use and it must be unique. A configuration name should not be changed if there are users or admins using it.

SFTPGo can use 2FA for `HTTP`, `SSH` (SFTP, SCP) and `FTP` protocols. If you plan to use 2FA with `SSH` you have to enable the keyboard interactive authentication which is disabled by default.

```json
  "sftpd": {
    ...
    "keyboard_interactive_authentication": true,
    ...
```

## Enable 2FA for admins

Each admin can view/change his/her two-factor authentication by selecting the `Two-Factor Auth` link from the top-right web UI menu.

![Admin 2FA](./img/admin-2FA.png)

Then select a configuration and click "Generate new secret". A QR code will be generated which you can scan with a compatible app. After you configured your app, enter a test code to ensure everything works correctly and click on "Verify and save".

![Enable 2FA](./img/admin-save-2FA.png)

SFTPGo automatically generates some recovery codes. They are a set of one time use codes that can be used in place of the TOTP to login to the web UI. You can use them if you lose access to your phone to login to your account and disable or regenerate TOTP configuration.

2FA is now enabled, so the next time you login with this admin you have to provide a valid authentication code after your password.

![Login with 2FA](./img/admin-2FA-login.png)

Two-factor authentication will also be required to use the REST API as this admin. You can provide the authentication code using the `X-SFTPGO-OTP` HTTP header.

If an admin loses access to their second factor auth device and has no recovery codes, another admin can disable second factor authentication for him/her using the `/api/v2/admins/{username}/2fa/disable` REST endpoint.

For example:

```shell
curl -X 'PUT' \
  'http://localhost:8080/api/v2/admins/admin/2fa/disable' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiQVBJIl0sImV4cCI6MTYzOTkzMTE3MiwianRpIjoiYzZ2bGd0NjEwZDFxYjZrdTBiNWciLCJuYmYiOjE2Mzk5Mjk5NDIsInBlcm1pc3Npb25zIjpbIioiXSwic3ViIjoiV20rYTF2bnVVc1VRYXA0TVZmSGtseWxObmR4TCswYVM3OVVjc1hXZitzdz0iLCJ1c2VybmFtZSI6ImFkbWluMSJ9.043lQFq7WRfJ-rdoCbp_TXEHbAo8Ihj5CAh3k8JQVQQ'
```

If you prefer a web UI instead of a CLI command to disable 2FA you can use the swagger UI interface available, by default, at the following URL `http://localhost:8080/openapi/swagger-ui`.

## Enable 2FA for users

Two-factor authentication is enabled by default for all SFTPGo users. Admins can disable 2FA per-user by selecting `mfa-disabled` in the Web client/REST API restrictions.

![User 2FA disabled](./img/user-2FA-disabled.png)

If 2FA is not disabled each user can enable it by selecting "Two-factor auth" from the left menu in the web UI.

Users can enable 2FA for HTTP, SSH and FTP protocols.

SSH protocol (SFTP/SCP/SSH commands) will ask for the passcode if the client uses keyboard interactive authentication.

HTTP protocol means Web UI and REST APIs. Web UI will ask for the passcode using a specific page. For REST APIs you have to specify the passcode using the `X-SFTPGO-OTP` HTTP header.

FTP has no standard way to support two factor authentication, if you enable the FTP protocol, you have to add the TOTP passcode after the password. For example if your password is "password" and your one time passcode is "123456" you have to use "password123456" as password.

To enable 2FA select the wanted protocols, a configuration and click "Generate new secret". A QR code will be generated which you can scan with a compatible app. After you configured your app, enter a test code to ensure everything works correctly and click on "Verify and save".

![Enable 2FA](./img/user-save-2FA.png)

SFTPGo automatically generates some recovery codes. They are a set of one time use codes that can be used in place of the TOTP to login to the web UI. You can use them if you lose access to your phone to login to your account and disable or regenerate TOTP configuration.

2FA is now enabled, so the next time you login with this user you have to provide a valid authentication code after your password.

![Login with 2FA](./img/user-2FA-login.png)

Two-factor authentication will be also required to use the REST API as this user. You can provide the authentication code using the `X-SFTPGO-OTP` header.

If this user tries to login via SFTP it must provide a valid authentication code after the password.

```shell
$ sftp -P 2022 nicola@127.0.0.1
(nicola@127.0.0.1) Password:
(nicola@127.0.0.1) Authentication code:
Connected to 127.0.0.1.
sftp> quit
```

If a user loses access to their second factor auth device and has no recovery codes then an admin can disable the second factor authentication using the `/api/v2/users/{username}/2fa/disable` REST endpoint.

For example:

```shell
curl -X 'PUT' \
  'http://localhost:8080/api/v2/users/nicola/2fa/disable' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiQVBJIl0sImV4cCI6MTYzOTkzMzI1MywianRpIjoiYzZ2bTE1ZTEwZDFxcG9iamc3djAiLCJuYmYiOjE2Mzk5MzIwMjMsInBlcm1pc3Npb25zIjpbIioiXSwic3ViIjoiV20rYTF2bnVVc1VRYXA0TVZmSGtseWxObmR4TCswYVM3OVVjc1hXZitzdz0iLCJ1c2VybmFtZSI6ImFkbWluMSJ9.ntR0L2JTuwYwhBy6c0iu10rdmycLdtKZtmDObQ0PUoo'
```

If you prefer a web UI instead of a CLI command to disable 2FA you can use the swagger UI interface available, by default, at the following URL `http://localhost:8080/openapi/swagger-ui`.
