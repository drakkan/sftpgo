# Web Client

SFTPGo provides a basic front-end web interface for your users. It allows end-users to browse and download their files and change their credentials.

The web interface can be globally disabled within the `httpd` configuration via the `enable_web_client` key or on a per-user basis by adding `HTTP` to the denied protocols.
Public keys management can be disabled, per-user, using a specific permission.

With the default `httpd` configuration, the web admin is available at the following URL:

[http://127.0.0.1:8080/web/client](http://127.0.0.1:8080/web/client)
