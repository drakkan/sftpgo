# Web Admin

You can easily build your own interface using the exposed [REST API](./rest-api.md). Anyway, SFTPGo also provides a basic built-in web interface that allows you to manage users, virtual folders, admins and connections.
With the default `httpd` configuration, the web admin is available at the following URL:

[http://127.0.0.1:8080/web](http://127.0.0.1:8080/web)

The default credentials are:

- username: `admin`
- password: `password`

The web interface can be exposed via HTTPS and may require mutual TLS authentication in addition to administrator credentials.
