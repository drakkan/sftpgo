# Expose Web Admin and REST API over HTTPS and password protected

This tutorial shows how to expose the SFTPGo web interface and REST API over HTTPS and password protect them.

## Preliminary Note

Before proceeding further you need to have a SFTPGo instance already configured and running.

We assume:

- you are running SFTPGo as service using the dedicated `sftpgo` system user
- the SFTPGo configuration directory is `/etc/sftpgo`
- you are running SFTPGo on Ubuntu 20.04, however this instructions can be easily adapted for other Linux variants.

## Authentication Setup

First install the `htpasswd` tool. We use this tool to create the users for the Web Admin/REST API.

```shell
sudo apt install apache2-utils
```

Create a user for web based authentication.

```shell
sudo htpasswd -B -c /etc/sftpgo/httpauth sftpgoweb
```

If you want to create additional users omit the `-c` option.

```shell
sudo htpasswd -B /etc/sftpgo/httpauth anotheruser
```

Next open the SFTPGo configuration.

```shell
sudo vi /etc/sftpgo/sftpgo.json
```

Search for the `httpd` section and change it as follow.

```json
  "httpd": {
    "bind_port": 8080,
    "bind_address": "",
    "templates_path": "templates",
    "static_files_path": "static",
    "backups_path": "backups",
    "auth_user_file": "/etc/sftpgo/httpauth",
    "certificate_file": "",
    "certificate_key_file": ""
  }
```

Setting an empty `bind_address` means that the service will listen on all available network interfaces and so it will be exposed over the network.

Now restart the SFTPGo service to apply the changes.

```shell
systemctl restart sftpgo
```

You are done! Now login to the Web Admin interface using the username and password created above.

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
    "bind_port": 8080,
    "bind_address": "",
    "templates_path": "templates",
    "static_files_path": "static",
    "backups_path": "backups",
    "auth_user_file": "/etc/sftpgo/httpauth",
    "certificate_file": "/etc/sftpgo/ssl/sftpgo.crt",
    "certificate_key_file": "/etc/sftpgo/ssl/sftpgo.key"
  }
```

Now restart the SFTPGo service to apply the changes.

```shell
systemctl restart sftpgo
```

You are done! Now SFTPGo web admin and REST API are exposed over HTTPS and password protected.

You can easily replace the self-signed certificate used here with a properly signed certificate.

The certificate could frequently change if you use something like [let's encrypt](https://letsencrypt.org/). SFTPGo allows hot-certificate reloading using the following command.

```shell
sudo systemctl reload sftpgo
```
