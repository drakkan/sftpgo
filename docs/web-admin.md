# Web Admin

You can easily build your own interface using the exposed [REST API](./rest-api.md). Anyway, SFTPGo also provides a basic built-in web interface that allows you to manage users, virtual folders, admins and connections.
With the default `httpd` configuration, the web admin is available at the following URL:

[http://127.0.0.1:8080/web/admin](http://127.0.0.1:8080/web/admin)

If no admin user is found within the data provider, typically after the initial installation, SFTPGo will ask you to create the first admin. You can also pre-create an admin user by loading initial data or by enabling the `create_default_admin` configuration key. Please take a look [here](./full-configuration.md) for more details.

The web interface can be exposed via HTTPS and may require mutual TLS authentication in addition to administrator credentials.
