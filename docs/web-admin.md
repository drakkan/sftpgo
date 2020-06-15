# Web Admin

You can easily build your own interface using the exposed REST API. Anyway, SFTPGo also provides a very basic built-in web interface that allows you to manage users and connections.
With the default `httpd` configuration, the web admin is available at the following URL:

[http://127.0.0.1:8080/web](http://127.0.0.1:8080/web)

The web interface can be protected using HTTP basic authentication and exposed via HTTPS. If you need more advanced security features, you can setup a reverse proxy as explained for the [REST API](./rest-api.md).
