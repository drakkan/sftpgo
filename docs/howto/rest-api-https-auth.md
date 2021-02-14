# Expose Web Admin and REST API over HTTPS

This tutorial shows how to expose the SFTPGo web interface and REST API over HTTPS.

## Preliminary Note

Before proceeding further you need to have a SFTPGo instance already configured and running.

We assume:

- you are running SFTPGo as service using the dedicated `sftpgo` system user
- the SFTPGo configuration directory is `/etc/sftpgo`
- you are running SFTPGo on Ubuntu 20.04, however this instructions can be easily adapted for other Linux variants.

## Creation of a Self-Signed Certificate

For demostration purpose we use a self-signed certificate here. These certificates are easy to make and do not cost money. However, they do not provide all of the security properties that certificates signed by a Public Certificate Authority (CA) aim to provide, you are encouraged to use a certificate signed by a Public CA.

When creating a new SSL certificate, one needs to specify the duration validity of the same by changing the value 365 (as appearing in the message below) to the preferred number of days. It is important to mention here that the certificate so created stands to auto-expire upon completion of one year.

```shell
sudo mkdir /etc/sftpgo/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/sftpgo/ssl/sftpgo.key -out /etc/sftpgo/ssl/sftpgo.crt
```

The above command is rather versatile, and lets you create both the self-signed SSL certificate and the server key to safeguard it, in addition to placing both of these into the `etc/sftpgo/ssl` directory. Answer to the questions to create the certificate and the key for HTTPS.

Assign the proper permissions to the generated certificates.

```shell
sudo chown -R sftpgo:sftpgo /etc/sftpgo/ssl
```

## HTTPS Setup

Open the SFTPGo configuration.

```shell
sudo vi /etc/sftpgo/sftpgo.json
```

Search for the `httpd` section and change it as follow.

```json
  "httpd": {
    "bindings": [
      {
        "port": 8080,
        "address": "",
        "enable_web_admin": true,
        "enable_https": false,
        "client_auth_type": 0
      }
    ],
    "templates_path": "/usr/share/sftpgo/templates",
    "static_files_path": "/usr/share/sftpgo/static",
    "backups_path": "/srv/sftpgo/backups",
    "certificate_file": "/etc/sftpgo/ssl/sftpgo.crt",
    "certificate_key_file": "/etc/sftpgo/ssl/sftpgo.key",
    "ca_certificates": [],
    "ca_revocation_lists": []
  },
```

The configuration keys `certificate_file` and `certificate_key_file` point to the certificate and key we previously created. Setting an empty `address` means that the service will listen on all available network interfaces.

Now restart the SFTPGo service to apply the changes.

```shell
sudo systemctl restart sftpgo
```

You are done! Now SFTPGo web admin and REST API are exposed over HTTPS.

You can easily replace the self-signed certificate used here with a properly signed certificate.

The certificate could frequently change if you use something like [let's encrypt](https://letsencrypt.org/). SFTPGo allows hot-certificate reloading using the following command.

```shell
sudo systemctl reload sftpgo
```
