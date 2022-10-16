# Securing SFTPGo with a free Let's Encrypt TLS Certificate

This tutorial shows how to obtain and renew a free Let's encrypt TLS certificate for the SFTPGo Web UI and REST API, the WebDAV service and the FTP service.

Obtaining a Let's Encrypt certificate involves solving a domain validation challenge issued by an ACME (Automatic Certificate Management Environment) server. This challenge verifies your ownership of the domain(s) you're trying to obtain a certificate for. Different challenge types exist, the most commonly used being `HTTP-01`. As its name suggests, it uses the HTTP protocol. While HTTP servers can be configured to use any TCP port, this challenge will only work on port `80` due to security measures.

More info about the supported challenge types can be found [here](https://letsencrypt.org/docs/challenge-types/).

There are several tools that allow you to obtain a Let's encrypt TLS certificate, in this tutorial we'll show how to use the [lego](https://github.com/go-acme/lego) CLI tool and the ACME protocol built into SFTPGo.

The `lego` CLI supports all the Let's encrypt challenge types.
The ACME protocol built into SFTPGo supports `HTTP-01` and `TLS-ALPN-01` challenge types.

In this tutorial we'll focus on `HTTP-01` challenge type and make the following assumptions:

- we are running SFTPGo on Linux
- we need a TLS certificate for the `sftpgo.com` domain
- we have an existing web server already running on port `80` for the `sftpgo.com` domain and the web root path is `/var/www/sftpgo.com`

## Overview

- [Obtaining a certificate using the Lego CLI tool](#Obtaining-a-certificate-using-the-Lego-CLI-tool)
  - [Automatic certificate renewal using the Lego CLI tool](#Automatic-certificate-renewal-using-the-Lego-CLI-tool)
- [Obtaining a certificate using the ACME protocol built into SFTPGo](#Obtaining-a-certificate-using-the-ACME-protocol-built-into-SFTPGo)
- [Enable HTTPS for SFTPGo Web UI and REST API](#Enable-HTTPS-for-SFTPGo-Web-UI-and-REST-API)
- [Enable HTTPS for WebDAV service](#Enable-HTTPS-for-WebDAV-service)
- [Enable explicit FTP over TLS](#Enable-explicit-FTP-over-TLS)

## Obtaining a certificate using the Lego CLI tool

Download the latest [lego release](https://github.com/go-acme/lego/releases) and extract the lego binary in `/usr/local/bin`, then verify that it works.

```shell
lego -v
lego version 4.4.0 linux/amd64
```

We'll store the certificates in `/var/lib/lego` so create this directory.

```shell
sudo mkdir -p /var/lib/lego
```

Now obtain a certificate. The HTTP based challenge will be created in a file in `/var/www/sftpgo.com/.well-known/acme-challenge`. This directory must be publicly served by your web server.

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
sudo mkdir -p /var/lib/sftpgo/certs
sudo cp /var/lib/lego/certificates/sftpgo.com.{crt,key} /var/lib/sftpgo/certs
sudo chown -R sftpgo:sftpgo /var/lib/sftpgo/certs
```

### Automatic certificate renewal using the Lego CLI tool

SFTPGo can reload TLS certificates without service interruption, so we'll create a small bash script that copies the certificates inside the SFTPGo private directory and instructs SFTPGo to load them. We then configure `lego` to run this script when the certificates are renewed.

Create the file `/usr/local/bin/sftpgo_lego_hook` with the following contents.

```shell
#!/bin/bash

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

CERTS_DIR=/var/lib/sftpgo/certs
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
{"level":"debug","time":"2021-06-14T20:05:15.785","sender":"httpd","message":"TLS certificate \"/var/lib/sftpgo/certs/sftpgo.com.crt\" successfully loaded"}
{"level":"debug","time":"2021-06-14T20:05:15.785","sender":"ftpd","message":"TLS certificate \"/var/lib/sftpgo/certs/sftpgo.com.crt\" successfully loaded"}
{"level":"debug","time":"2021-06-14T20:05:15.786","sender":"webdavd","message":"TLS certificate \"/var/lib/sftpgo/certs/sftpgo.com.crt\" successfully loaded"}
```

## Obtaining a certificate using the ACME protocol built into SFTPGo

You can open the SFTPGo configuration file, search for the `acme` section and change it as follow.

```json
  "acme": {
    "domains": ["sftpgo.com"],
    "email": "<you email address here>",
    "key_type": "4096",
    "certs_path": "/var/lib/sftpgo/certs",
    "ca_endpoint": "https://acme-v02.api.letsencrypt.org/directory",
    "renew_days": 30,
    "http01_challenge": {
      "port": 80,
      "proxy_header": "",
      "webroot": "/var/www/sftpgo.com"
    },
    "tls_alpn01_challenge": {
      "port": 0
    }
  }
```

Alternatively (recommended), you can use environment variables by creating the file `/etc/sftpgo/env.d/acme.env` with the following content.

```shell
SFTPGO_ACME__DOMAINS="sftpgo.com"
SFTPGO_ACME__EMAIL="<you email address here>"
SFTPGO_ACME__HTTP01_CHALLENGE__WEBROOT="/var/www/sftpgo.com"
```

Make sure that the `sftpgo` user can write to the `/var/www/sftpgo.com` directory or pre-create the `/var/www/sftpgo.com/.well-known/acme-challenge` directory with the appropriate permissions.
This directory must be publicly served by your web server.

Register your account and obtain certificates by running the following command.

```bash
sudo -E su - sftpgo -m -s /bin/bash -c 'sftpgo acme run -c /etc/sftpgo'
```

If this command completes successfully, you are done. The SFTPGo service will take care of the automatic renewal of certificates for the configured domains. Make sure that the `sftpgo` system user can read and write to `/var/lib/sftpgo/certs` directory otherwise the certificate renewal will fail.

## Enable HTTPS for SFTPGo Web UI and REST API

You can open the SFTPGo configuration file, search for the `httpd` section and change it as follow.

```json
  "httpd": {
    "bindings": [
      {
        "port": 9443,
        "address": "",
        "enable_web_admin": true,
        "enable_web_client": true,
        "enable_rest_api": true,
        "enable_https": true,
        "certificate_file": "/var/lib/sftpgo/certs/sftpgo.com.crt",
        "certificate_key_file": "/var/lib/sftpgo/certs/sftpgo.com.key",
        .....
```

Alternatively (recommended), you can use environment variables by creating the file `/etc/sftpgo/env.d/httpd.env` with the following content.

```shell
SFTPGO_HTTPD__BINDINGS__0__PORT=9443
SFTPGO_HTTPD__BINDINGS__0__ENABLE_HTTPS=1
SFTPGO_HTTPD__BINDINGS__0__CERTIFICATE_FILE="/var/lib/sftpgo/certs/sftpgo.com.crt"
SFTPGO_HTTPD__BINDINGS__0__CERTIFICATE_KEY_FILE="/var/lib/sftpgo/certs/sftpgo.com.key"
```

Restart SFTPGo to apply the changes. The HTTPS service is now available on port `9443`.

## Enable HTTPS for WebDAV service

You can open the SFTPGo configuration file, search for the `webdavd` section and change it as follow.

```json
  "webdavd": {
    "bindings": [
      {
        "port": 10443,
        "address": "",
        "enable_https": true,
        "certificate_file": "/var/lib/sftpgo/certs/sftpgo.com.crt",
        "certificate_key_file": "/var/lib/sftpgo/certs/sftpgo.com.key",
        ...
```

Alternatively (recommended), you can use environment variables by creating the file `/etc/sftpgo/env.d/webdavd.env` with the following content.

```shell
SFTPGO_WEBDAVD__BINDINGS__0__PORT=10443
SFTPGO_WEBDAVD__BINDINGS__0__ENABLE_HTTPS=1
SFTPGO_WEBDAVD__CERTIFICATE_FILE="/var/lib/sftpgo/certs/sftpgo.com.crt"
SFTPGO_WEBDAVD__CERTIFICATE_KEY_FILE="/var/lib/sftpgo/certs/sftpgo.com.key"
```

Restart SFTPGo to apply the changes. WebDAV is now availble over HTTPS on port `10443`.

## Enable explicit FTP over TLS

You can open the SFTPGo configuration file, search for the `ftpd` section and change it as follow.

```json
  "ftpd": {
    "bindings": [
      {
        "port": 2121,
        "address": "",
        "apply_proxy_config": true,
        "tls_mode": 1,
        "certificate_file": "/var/lib/sftpgo/certs/sftpgo.com.crt",
        "certificate_key_file": "/var/lib/sftpgo/certs/sftpgo.com.key",
        ...
```

Alternatively (recommended), you can use environment variables by creating the file `/etc/sftpgo/env.d/ftpd.env` with the following content.

```shell
SFTPGO_FTPD__BINDINGS__0__PORT=2121
SFTPGO_FTPD__BINDINGS__0__TLS_MODE=1
SFTPGO_FTPD__BINDINGS__0__CERTIFICATE_FILE="/var/lib/sftpgo/certs/sftpgo.com.crt"
SFTPGO_FTPD__BINDINGS__0__CERTIFICATE_KEY_FILE="/var/lib/sftpgo/certs/sftpgo.com.key"
```

Restart SFTPGo to apply the changes. FTPES service is now available on port `2121` and TLS is required for both control and data connection (`tls_mode` is 1).
