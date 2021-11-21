# Securing SFTPGo with a free Let's Encrypt TLS Certificate

This tutorial shows how to create and configure a free Let's encrypt TLS certificate for the SFTPGo Web UI and REST API, the WebDAV service and the FTP service.

Obtaining a Let's Encrypt certificate involves solving a domain validation challenge issued by an ACME (Automatic Certificate Management Environment) server. This challenge verifies your ownership of the domain(s) you're trying to obtain a certificate for. Different challenge types exist, the most commonly used being `HTTP-01`. As its name suggests, it uses the HTTP protocol. While HTTP servers can be configured to use any TCP port, this challenge will only work on port 80 due to security measures.

More info about the supported challenge types can be found [here](https://letsencrypt.org/docs/challenge-types/).

There are several tools that allow you to obtain a Let's encrypt TLS certificate, in this tutorial we'll use the [lego](https://github.com/go-acme/lego) CLI.

The `lego` CLI supports all the Let's encrypt challenge types, in this tutorial we'll focus on `HTTP-01` challenge type and make the following assumptions:

- we are running SFTPGo on Linux
- we need a TLS certificate for the `sftpgo.com` domain
- we have an existing web server already running on port 80 for the `sftpgo.com` domain and the web root path is `/var/www/sftpgo.com`

## Obtaining a certificate

Download the latest [lego release](https://github.com/go-acme/lego/releases) and extract the lego binary in `/usr/local/bin`, then verify that it works.

```shell
lego -v
lego version 4.4.0 linux/amd64
```

We'll store the certificates in `/var/lib/lego` so create this directory.

```shell
sudo mkdir -p /var/lib/lego
```

Now get a certificate. The HTTP based challenge will be created in a file in `/var/www/sftpgo.com/.well-known/acme-challenge`. This directory must be publicly served by your web server.

```shell
sudo lego --accept-tos --path="/var/lib/lego" --email="<you email address here>" --domains="sftpgo.com" --http.webroot="/var/www/sftpgo.com" --http run
```

You should be now able to list your certificate.

```shell
sudo lego --path="/var/lib/lego" list
Found the following certs:
  Certificate Name: sftpgo.com
    Domains: sftpgo.com
    Expiry Date: 2021-09-09 19:41:51 +0000 UTC
    Certificate Path: /var/lib/lego/certificates/sftpgo.com.crt
```

Now copy the certificate inside a private path to the SFTPGo service.

```shell
sudo mkdir -p /etc/sftpgo/certs
sudo cp /var/lib/lego/certificates/sftpgo.com.{crt,key} /etc/sftpgo/certs
sudo chown -R sftpgo:sftpgo /etc/sftpgo/certs
```

## Enable HTTPS for SFTPGo Web UI and REST API

Open the SFTPGo configuration file, search for the `httpd` section and change it as follow.

```json
  "httpd": {
    "bindings": [
      {
        "port": 9443,
        "address": "",
        "enable_web_admin": true,
        "enable_web_client": true,
        "enable_https": true,
        "client_auth_type": 0,
        "tls_cipher_suites": [],
        "proxy_allowed": [],
        "hide_login_url": 0,
        "render_openapi": true
      }
    ],
    "templates_path": "/usr/share/sftpgo/templates",
    "static_files_path": "/usr/share/sftpgo/static",
    "backups_path": "/srv/sftpgo/backups",
    "openapi_path": "/srv/sftpgo/openapi",
    "web_root": "",
    "certificate_file": "/etc/sftpgo/certs/sftpgo.com.crt",
    "certificate_key_file": "/etc/sftpgo/certs/sftpgo.com.key",
    "ca_certificates": [],
    "ca_revocation_lists": [],
    ....
  }
```

Restart SFTPGo to apply the changes. The HTTPS service is now available on port `9443`.

## Enable HTTPS for WebDAV service

Open the SFTPGo configuration file, search for the `webdavd` section and change it as follow.

```json
  "webdavd": {
    "bindings": [
      {
        "port": 10443,
        "address": "",
        "enable_https": true,
        "client_auth_type": 0,
        "tls_cipher_suites": [],
        "prefix": "",
        "proxy_allowed": []
      }
    ],
    "certificate_file": "/etc/sftpgo/certs/sftpgo.com.crt",
    "certificate_key_file": "/etc/sftpgo/certs/sftpgo.com.key",
    ...
```

Restart SFTPGo to apply the changes. WebDAV is now availble over HTTPS on port `10443`.

## Enable explicit FTP over TLS

Open the SFTPGo configuration file, search for the `ftpd` section and change it as follow.

```json
  "ftpd": {
    "bindings": [
      {
        "port": 2121,
        "address": "",
        "apply_proxy_config": true,
        "tls_mode": 1,
        "force_passive_ip": "",
        "client_auth_type": 0,
        "tls_cipher_suites": []
      }
    ],
    "banner": "",
    "banner_file": "",
    "active_transfers_port_non_20": true,
    "passive_port_range": {
      "start": 50000,
      "end": 50100
    },
    "disable_active_mode": false,
    "enable_site": false,
    "hash_support": 0,
    "combine_support": 0,
    "certificate_file": "/etc/sftpgo/certs/sftpgo.com.crt",
    "certificate_key_file": "/etc/sftpgo/certs/sftpgo.com.key",
    "ca_certificates": [],
    "ca_revocation_lists": []
  }
```

Restart SFTPGo to apply the changes. FTPES service is now available on port `2121` and TLS is required for both control and data connection (`tls_mode` is 1).

## Automatic certificate renewal

SFTPGo can reload TLS certificates without service interruption, so we'll create a small bash script that copies the certificates inside the SFTPGo private directory and instructs SFTPGo to load them. We then configure `lego` to run this script when the certificates are renewed.

Create the file `/usr/local/bin/sftpgo_lego_hook` with the following contents.

```shell
#!/bin/bash

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

CERTS_DIR=/etc/sftpgo/certs
mkdir -p ${CERTS_DIR}

cp ${LEGO_CERT_PATH} ${LEGO_CERT_KEY_PATH} ${CERTS_DIR}

chown -R sftpgo:sftpgo ${CERTS_DIR}
systemctl reload sftpgo
```

Ensure that this script is executable.

```shell
sudo chmod 755 /usr/local/bin/sftpgo_lego_hook
```

Now create a daily cron job to check the certificate expiration and renew it if necessary. For example create the file `/etc/cron.daily/lego` with the following contents.

```shell
#!/bin/bash

lego --accept-tos --path="/var/lib/lego" --email="<you email address here>" --domains="sftpgo.com" --http-timeout 60 --http.webroot="/var/www/sftpgo.com" --http renew --renew-hook="/usr/local/bin/sftpgo_lego_hook"
```

Ensure that this cron script is executable.

```shell
sudo chmod 755 /etc/cron.daily/lego
```

When the certificate is renewed you should see SFTPGo logs like the following to confirm that the new certificate was successfully loaded.

```json
{"level":"debug","time":"2021-06-14T20:05:15.785","sender":"service","message":"Received reload request"}
{"level":"debug","time":"2021-06-14T20:05:15.785","sender":"httpd","message":"TLS certificate \"/etc/sftpgo/certs/sftpgo.com.crt\" successfully loaded"}
{"level":"debug","time":"2021-06-14T20:05:15.785","sender":"ftpd","message":"TLS certificate \"/etc/sftpgo/certs/sftpgo.com.crt\" successfully loaded"}
{"level":"debug","time":"2021-06-14T20:05:15.786","sender":"webdavd","message":"TLS certificate \"/etc/sftpgo/certs/sftpgo.com.crt\" successfully loaded"}
```
