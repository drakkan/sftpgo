# REST API

SFTPGo exposes REST API to manage, backup, and restore users and folders, and to get real time reports of the active connections with the ability to forcibly close a connection.

If quota tracking is enabled in the configuration file, then the used size and number of files are updated each time a file is added/removed. If files are added/removed not using SFTP/SCP, or if you change `track_quota` from `2` to `1`, you can rescan the users home dir and update the used quota using the REST API.

REST API are protected using JSON Web Tokens (JWT) authentication and can be exposed over HTTPS. You can also configure client certificate authentication in addition to JWT.

The default credentials are:

- username: `admin`
- password: `password`

You can get a JWT token using the `/api/v2/token` endpoint, you need to authenticate using HTTP Basic authentication and the credentials of an active administrator. Here is a sample response:

```json
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTA4NzU5NDksImp0aSI6ImMwMjAzbGZjZHJwZDRsMGMxanZnIiwibmJmIjoxNjEwODc1MzE5LCJwZXJtaXNzaW9ucyI6WyIqIl0sInN1YiI6ImlHZ010NlZNU3AzN2tld3hMR3lUV1l2b2p1a2ttSjBodXlJZHBzSWRyOFE9IiwidXNlcm5hbWUiOiJhZG1pbiJ9.dt-UwcWdEMwoGauuiQw8BmgpBAv4YlTaXkyNK-7iRJ4","expires_at":"2021-01-17T09:32:29Z"}
```

once the access token has expired, you need to get a new one.

JWT tokens are not stored and we use a randomly generated secret to sign them so if you restart SFTPGo all the previous tokens will be invalidated and you will get a 401 HTTP response code.

If you define multiple bindings, each binding will sign JWT tokens with a different secret so the token generated for a binding is not valid for the other ones.

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
- manage system
- manage admins

You can also restrict administrator access based on the source IP address. If you are running SFTPGo behind a reverse proxy you need to allow both the proxy IP address and the real client IP.

The OpenAPI 3 schema for the exposed API can be found inside the source tree: [openapi.yaml](../httpd/schema/openapi.yaml "OpenAPI 3 specs"). If you want to render the schema without importing it manually, you can explore it on [Stoplight](https://sftpgo.stoplight.io/docs/sftpgo/openapi.yaml).

You can generate your own REST client in your preferred programming language, or even bash scripts, using an OpenAPI generator such as [swagger-codegen](https://github.com/swagger-api/swagger-codegen) or [OpenAPI Generator](https://openapi-generator.tech/).

You can also use [Swagger UI](https://github.com/swagger-api/swagger-ui).
