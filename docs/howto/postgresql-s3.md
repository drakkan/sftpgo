# SFTPGo with PostgreSQL data provider and S3 backend

This tutorial shows the installation of SFTPGo on Ubuntu 20.04 (Focal Fossa) with PostgreSQL data provider and S3 backend. SFTPGo will run as an unprivileged (non-root) user. We assume that you want to serve a single S3 bucket and you want to assign different "virtual folders" of this bucket to different SFTPGo virtual users.

## Preliminary Note

Before proceeding further you need to have a basic minimal installation of Ubuntu 20.04.

Create the `sftpgo` user with the following command.

```shell
sudo adduser sftpgo
```

Type the user password and other info.

Add the `sftpgo` user to the `sudo` group so it will be able to use `sudo`:

```shell
sudo usermod -a -G sudo sftpgo
```

Now login using this user. Confirm that you are logged in as `sftpgo` user with the following command.

```shell
whoami
```

the output should be `sftpgo`.

NOTE: once you completed this tutorial you can, optionally, remove the user `sftpgo` from the `sudo` group with the following command.

```shell
sudo delgroup sftpgo sudo
```

## Install PostgreSQL

Before installing any packages on the Ubuntu system, update and upgrade all packages using the `apt` commands below.

```shell
sudo apt update
sudo apt upgrade
```

Install PostgreSQL with this `apt` command.

```shell
sudo apt -y install postgresql
```

Once installation is completed, start the PostgreSQL service and add it to the system boot.

```shell
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

Next, check the PostgreSQL service using the following command.

```shell
systemctl status postgresql
```

## Configure PostgreSQL

PostgreSQL uses roles for user authentication and authorization, it just like Unix-Style permissions. By default, PostgreSQL creates a new user called `postgres` for basic authentication.

In this step, we will create a new PostgreSQL user for SFTPGo.

Login to the PostgreSQL shell using the command below.

```shell
sudo -i -u postgres psql
```

Next, create a new role `sftpgo` with the password `sftpgo_pg_pwd` using the following query.

```sql
create user "sftpgo" with encrypted password 'sftpgo_pg_pwd';
```

Next, create a new database `sftpgo.db` for the SFTPGo service using the following queries.

```sql
create database "sftpgo.db";
grant all privileges on database "sftpgo.db" to "sftpgo";
```

Exit from the PostgreSQL shell typing `\q`.

## Configure AWS credentials

We assume that you want to serve a single S3 bucket and you want to assign different "virtual folders" of this bucket to different SFTPGo virtual users. In this case is very convenient to configure a credential file so SFTPGo will automatically use it and you don't need to specify the same AWS credentials for each user.

You can manually create the `~/.aws/credentials` file and write your AWS credentials like this.

```shell
[default]
aws_access_key_id=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Alternately you can install `AWS CLI` and manage the credential using this tool.

```shell
sudo apt install awscli
```

and now set your credentials, region, and output format with the following command.

```shell
aws configure
```

Confirm that you can list your bucket contents with the following command.

```shell
aws s3 ls s3://mybucket
```

## Install SFTPGo

Download a binary SFTPGo [release](https://github.com/drakkan/sftpgo/releases) or a build artifact for the [latest commit](https://github.com/drakkan/sftpgo/actions).

In this tutorial we assume you downloaded a build artifact named `sftpgo-ubuntu-latest-go1.15.zip` inside the current directory.

Install `unzip`, if not already installed, and extract the archive with the following commands.

```shell
sudo apt install unzip
mkdir sftpgo_installdir
unzip sftpgo-ubuntu-latest-go1.15.zip -d sftpgo_installdir
```

Now change the current directory to `sftpgo_installdir` and install SFTPGo.

```shell
cd sftpgo_installdir

# create the required directories
sudo mkdir -p /etc/sftpgo/hostkeys \
  /var/lib/sftpgo/credentials \
  /usr/share/sftpgo

# install the sftpgo executable
sudo install -Dm755 sftpgo /usr/bin/sftpgo
# install the default configuration file, edit it if required
sudo install -Dm644 sftpgo.json /etc/sftpgo/
# override some configuration keys using environment variables
sudo sh -c 'echo "SFTPGO_HTTPD__TEMPLATES_PATH=/usr/share/sftpgo/templates" > /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_HTTPD__STATIC_FILES_PATH=/usr/share/sftpgo/static" >> /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_HTTPD__BACKUPS_PATH=/var/lib/sftpgo/backups" >> /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_DATA_PROVIDER__CREDENTIALS_PATH=/var/lib/sftpgo/credentials" >> /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_SFTPD__HOST_KEYS=/etc/sftpgo/hostkeys/id_rsa,/etc/sftpgo/hostkeys/id_ecdsa" >> /etc/sftpgo/sftpgo.env'
# install static files and templates for the web UI
sudo cp -r static templates /usr/share/sftpgo/
# create bash completion script and man pages
sudo sh -c '/usr/bin/sftpgo gen completion bash > /etc/bash_completion.d/sftpgo-completion.bash'
sudo /usr/bin/sftpgo gen man -d /usr/share/man/man1
# enable bash completion
source /etc/bash_completion.d/sftpgo-completion.bash
# set proper permissions to run SFTPGo as non-root user
sudo chown -R sftpgo:sftpgo /etc/sftpgo/hostkeys /var/lib/sftpgo
```

## Configure SFTPGo

Now open the SFTPGo configuration.

```shell
sudo vi /etc/sftpgo/sftpgo.json
```

Search for the `data_provider` section and change it as follow.

```json
  "data_provider": {
    "driver": "postgresql",
    "name": "sftpgo.db",
    "host": "127.0.0.1",
    "port": 5432,
    "username": "sftpgo",
    "password": "sftpgo_pg_pwd",
    ...
    "users_base_dir": "/tmp",
}
```

This way we set the PostgreSQL connection parameters and a default base directory for new users.
Since we use S3 and not the local filesystem as backend we set `/tmp` as default base directory so when we add a new user the home directory will be automatically defined as the path obtained joining `/tmp` and the username.

If you want to connect to PostgreSQL over a Unix Domain socket you have to set the value `/var/run/postgresql` for the `host` configuration key instead of `127.0.0.1`.

You can further customize your configuration adding custom actions and other hooks. A full explanation of all configuration parameters can be found [here](../full-configuration.md).

Next, initialize the data provider with the following command.

```shell
$ sftpgo initprovider -c /etc/sftpgo
2020-09-12T21:07:50.000 DBG Initializing provider: "postgresql" config file: "/etc/sftpgo/sftpgo.json"
2020-09-12T21:07:50.000 DBG Data provider successfully initialized
```

## Install SFTPGo systemd service

Copy the systemd service file.

```shell
sudo install -Dm644 init/sftpgo.service /etc/systemd/system
```

Next, start the SFTPGo service and add it to the system boot.

```shell
sudo systemctl start sftpgo
sudo systemctl enable sftpgo
```

Next, check the SFTPGo service using the following command.

```shell
systemctl status sftpgo
```

## Add virtual users

The easiest way to add virtual users is to use the built-in Web interface.

You can expose the Web Admin interface over the network replacing `"bind_address": "127.0.0.1"` in the `httpd` configuration section with `"bind_address": ""` and apply the change restarting the SFTPGo service with the following command.

```shell
sudo systemctl restart sftpgo
```

So now open the Web Admin URL.

[http://127.0.0.1:8080/web](http://127.0.0.1:8080/web)

Click `Add` and fill the user details, the minimum required parameters are:

- `Username`
- `Password` or `Public keys`
- `Permissions`
- `Home Dir` can be empty since we defined a default base dir
- Select `Amazon S3 (Compatible)` as storage and then set `Bucket`, `Region` and optionally a `Key Prefix` if you want to restrict the user to a specific bucket virtual folder. The specified folder does not need to be pre-create. You can leave `Access Key` and `Access Secret` empty since we defined global credentials for the `sftpgo` user and we use this system user to run the SFTPGo service.

You are done! Now you can connect to you SFTPGo instance using any compatible `sftp` client on port `2022`.

You can mix S3 users with local users but please be aware that we are running the service as the unprivileged `sftpgo` system user so if you set storage as `local` for an SFTPGo virtual user then the home directory for this user need to be owned by the `sftpgo` system user.
