# REST API

SFTPGo exposes REST API to manage, backup, and restore users, and to get real time reports of the active connections with the ability to forcibly close a connection.

If quota tracking is enabled in the `sftpgo` configuration file, then the used size and number of files are updated each time a file is added/removed. If files are added/removed not using SFTP/SCP, or if you change `track_quota` from `2` to `1`, you can rescan the users home dir and update the used quota using the REST API.

REST API can be protected using HTTP basic authentication and exposed via HTTPS. If you need more advanced security features, you can setup a reverse proxy using an HTTP Server such as Apache or NGNIX.

For example, you can keep SFTPGo listening on localhost and expose it externally configuring a reverse proxy using Apache HTTP Server this way:

```
ProxyPass /api/v1 http://127.0.0.1:8080/api/v1
ProxyPassReverse /api/v1 http://127.0.0.1:8080/api/v1
```

and you can add authentication with something like this:

```
<Location /api/v1>
	AuthType Digest
	AuthName "Private"
	AuthDigestDomain "/api/v1"
	AuthDigestProvider file
	AuthUserFile "/etc/httpd/conf/auth_digest"
	Require valid-user
</Location>
```

and, of course, you can configure the web server to use HTTPS.

The OpenAPI 3 schema for the exposed API can be found inside the source tree: [openapi.yaml](./httpd/schema/openapi.yaml "OpenAPI 3 specs").

A sample CLI client for the REST API can be found inside the source tree [scripts](./scripts "scripts") directory.

You can also generate your own REST client in your preferred programming language, or even bash scripts, using an OpenAPI generator such as [swagger-codegen](https://github.com/swagger-api/swagger-codegen) or [OpenAPI Generator](https://openapi-generator.tech/)
