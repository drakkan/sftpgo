# Web Client

SFTPGo provides a basic front-end web interface for your users. It allows end-users to browse and manage their files and change their credentials.

Each authorized user can create HTTP/S links to externally share files and folders securely, by setting limits to the number of downloads/uploads, protecting the share with a password, limiting access by source IP address, setting an automatic expiration date.

The web client user interface also allows you to edit plain text files up to 512KB in size.

The web interface can be globally disabled within the `httpd` configuration via the `enable_web_client` key or on a per-user basis by adding `HTTP` to the denied protocols.
Public keys management can be disabled, per-user, using a specific permission.
The web client allows you to download multiple files or folders as a single zip file, any non regular files (for example symlinks) will be silently ignored.

With the default `httpd` configuration, the web client is available at the following URL:

[http://127.0.0.1:8080/web/client](http://127.0.0.1:8080/web/client)
