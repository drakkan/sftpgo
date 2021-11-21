# REST API

SFTPGo exposes REST API to manage, backup, and restore users and folders, data retention, and to get real time reports of the active connections with the ability to forcibly close a connection.

If quota tracking is enabled in the configuration file, then the used size and number of files are updated each time a file is added/removed. If files are added/removed not using SFTP/SCP, or if you change `track_quota` from `2` to `1`, you can rescan the users home dir and update the used quota using the REST API.

REST API are protected using JSON Web Tokens (JWT) authentication and can be exposed over HTTPS. You can also configure client certificate authentication in addition to JWT.

You can get a JWT token using the `/api/v2/token` endpoint, you need to authenticate using HTTP Basic authentication and the credentials of an active administrator. Here is a sample response:

```json
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTA4NzU5NDksImp0aSI6ImMwMjAzbGZjZHJwZDRsMGMxanZnIiwibmJmIjoxNjEwODc1MzE5LCJwZXJtaXNzaW9ucyI6WyIqIl0sInN1YiI6ImlHZ010NlZNU3AzN2tld3hMR3lUV1l2b2p1a2ttSjBodXlJZHBzSWRyOFE9IiwidXNlcm5hbWUiOiJhZG1pbiJ9.dt-UwcWdEMwoGauuiQw8BmgpBAv4YlTaXkyNK-7iRJ4","expires_at":"2021-01-17T09:32:29Z"}
```

once the access token has expired, you need to get a new one.

By default, JWT tokens are not stored and we use a randomly generated secret to sign them so if you restart SFTPGo all the previous tokens will be invalidated and you will get a 401 HTTP response code.

If you define multiple bindings, each binding will sign JWT tokens with a different secret so the token generated for a binding is not valid for the other ones.

If, instead, you want to use a persistent signing key for JWT tokens, you can define a signing passphrase via configuration file or environment variable.

You can create other administrator and assign them the following permissions:

- add users
- edit users
- del users
- view users
- view connections
- close connections
- view server status
- view and start quota scans
- view defender
- manage defender
- manage API keys
- manage system
- manage admins
- manage data retention
- view events

You can also restrict administrator access based on the source IP address. If you are running SFTPGo behind a reverse proxy you need to allow both the proxy IP address and the real client IP.

As alternative authentication method you can use API keys. API keys are mainly designed for machine-to-machine communications and a static API key is intrinsically less secure than a short lived JWT token. Although you can create permanent API keys it is recommended to set an expiration date. Additionally, a JWT token can be verified without further data provider queries while an API key requires one or more data provider queries to authenticate each request.

To generate API keys you first need to get a JWT token and then you can use the `/api/v2/apikeys` endpoint to manage your API keys.

The API keys allow the impersonation of users and administrators, using the API keys you inherit the permissions of the associated user/admin.

The user/admin association can be:

- static, a user/admin is explictly associated to the API key
- dynamic, the API key has no user/admin associated, you need to add ".username" at the end of the key to specificy the user/admin to impersonate. For example if your API key is `6ajKLwswLccVBGpZGv596G.ySAXc8vtp9hMiwAuaLtzof` and you want to impersonate the admin with username `myadmin` you have to use `6ajKLwswLccVBGpZGv596G.ySAXc8vtp9hMiwAuaLtzof.myadmin` as API key.

The API key scope defines if the API key can impersonate users or admins.
Before you can impersonate a user/admin you have to set `allow_api_key_auth` at user/admin level. Each user/admin can always revoke this permission.

The generated API key is returned in the response body when you create a new API key object. It is not stored as plain text, you need to save it after the initial creation, there is no way to display the API key as plain text after the initial creation.

API keys are not allowed for the following REST APIs:

- manage API keys itself. You cannot create, update, delete, enumerate API keys if you are logged in with an API key
- change password, public keys or second factor authentication for the associated user
- update the impersonated admin

Please keep in mind that using an API key not associated with any administrator it is still possible to create a new administrator, with full permissions, and then impersonate it: be careful if you share unassociated API keys with third parties and with the `manage adminis` permission granted, they will basically allow full access, the only restriction is that the impersonated admin cannot be modified.

The data retention APIs allow you to define per-folder retention policies for each user. To clarify this concept let's show an example, a data retention check accepts a POST body like this one:

```json
[
  {
    "path": "/folder1",
    "retention": 72
  },
  {
    "path": "/folder1/subfolder",
    "retention": 0
  },
  {
    "path": "/folder2",
    "retention": 24
  }
]
```

In the above example we asked to SFTPGo:

- to delete all the files with modification time older than 72 hours in `/folder1`
- to exclude `/folder1/subfolder`, no files will be deleted here
- to delete all the files with modification time older than 24 hours in `/folder2`

The check results can be, optionally, notified by e-mail.
You can find an example script that shows how to manage data retention [here](../examples/data-retention). Checks the REST API schema for full details.

:warning: Deleting files is an irreversible action, please make sure you fully understand what you are doing before using this feature, you may have users with overlapping home directories or virtual folders shared between multiple users, it is relatively easy to inadvertently delete files you need.

The OpenAPI 3 schema for the exposed API can be found inside the source tree: [openapi.yaml](../openapi/openapi.yaml "OpenAPI 3 specs"). You can render the schema and try the API using the `/openapi` endpoint. SFTPGo uses by default [Swagger UI](https://github.com/swagger-api/swagger-ui), you can use another renderer just by copying it to the defined OpenAPI path.

You can also explore the schema on [Stoplight](https://sftpgo.stoplight.io/docs/sftpgo/openapi.yaml).

You can generate your own REST API client in your preferred programming language, or even bash scripts, using an OpenAPI generator such as [swagger-codegen](https://github.com/swagger-api/swagger-codegen) or [OpenAPI Generator](https://openapi-generator.tech/).
