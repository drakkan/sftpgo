# SFTPGo with PostgreSQL data provider and S3 backend

This tutorial shows the installation of SFTPGo on Ubuntu 20.04 (Focal Fossa) with PostgreSQL data provider and S3 backend. SFTPGo will run as an unprivileged (non-root) user. We assume that you want to serve a single S3 bucket and you want to assign different "virtual folders" of this bucket to different SFTPGo virtual users.

## Preliminary Note

Before proceeding further you need to have a basic minimal installation of Ubuntu 20.04.

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

## Install SFTPGo

To install SFTPGo you can use the PPA [here](https://launchpad.net/~sftpgo/+archive/ubuntu/sftpgo).

Start by adding the PPA.

```shell
sudo add-apt-repository ppa:sftpgo/sftpgo
sudo apt-get update
```

Next install SFTPGo.

```shell
sudo apt install sftpgo
```

After installation SFTPGo should already be running with default configuration and configured to start automatically at boot, check its status using the following command.

```shell
systemctl status sftpgo
```

## Configure AWS credentials

We assume that you want to serve a single S3 bucket and you want to assign different "virtual folders" of this bucket to different SFTPGo virtual users. In this case is very convenient to configure a credential file so SFTPGo will automatically use it and you don't need to specify the same AWS credentials for each user.

You can manually create the `/var/lib/sftpgo/.aws/credentials` file and write your AWS credentials like this.

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

The AWS CLI will create the credential file in `~/.aws/credentials`. The SFTPGo service runs using the `sftpgo` system user whose home directory is `/var/lib/sftpgo` so you need to copy the credentials file to the sftpgo home directory and assign it the proper permissions.

```shell
sudo mkdir /var/lib/sftpgo/.aws
sudo cp ~/.aws/credentials /var/lib/sftpgo/.aws/
sudo chown -R sftpgo:sftpgo /var/lib/sftpgo/.aws
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
}
```

This way we set the PostgreSQL connection parameters.

If you want to connect to PostgreSQL over a Unix Domain socket you have to set the value `/var/run/postgresql` for the `host` configuration key instead of `127.0.0.1`.

You can further customize your configuration adding custom actions and other hooks. A full explanation of all configuration parameters can be found [here](../full-configuration.md).

Next, initialize the data provider with the following command.

```shell
$ sudo su - sftpgo -s /bin/bash -c 'sftpgo initprovider -c /etc/sftpgo'
2020-10-09T21:07:50.000 INF Initializing provider: "postgresql" config file: "/etc/sftpgo/sftpgo.json"
2020-10-09T21:07:50.000 INF updating database version: 1 -> 2
2020-10-09T21:07:50.000 INF updating database version: 2 -> 3
2020-10-09T21:07:50.000 INF updating database version: 3 -> 4
2020-10-09T21:07:50.000 INF Data provider successfully initialized/updated
```

The default sftpgo systemd service will start after the network target, in this setup it is more appropriate to start it after the PostgreSQL service, so edit the service using the following command.

```shell
sudo systemctl edit sftpgo.service
```

And override the unit definition with the following snippet.

```shell
[Unit]
After=postgresql.service
```

Confirm that `sftpgo.service` will start after `postgresql.service` with the next command.

```shell
$ systemctl show sftpgo.service | grep After=
After=postgresql.service systemd-journald.socket system.slice -.mount systemd-tmpfiles-setup.service network.target sysinit.target basic.target
```

Next restart the sftpgo service to use the new configuration and check that it is running.

```shell
sudo systemctl restart sftpgo
systemctl status sftpgo
```

## Create the first admin

To start using SFTPGo you need to create an admin user, the easiest way is to use the built-in Web admin interface, so open the Web Admin URL and create the first admin user.

[http://127.0.0.1:8080/web/admin](http://127.0.0.1:8080/web/admin)

## Add virtual users

The easiest way to add virtual users is to use the built-in Web interface.

So navigate to the Web Admin URL again and log in using the credentials you just set up.

[http://127.0.0.1:8080/web/admin](http://127.0.0.1:8080/web/admin)

Click `Add` and fill the user details, the minimum required parameters are:

- `Username`
- `Password` or `Public keys`
- `Permissions`
- `Home Dir` can be empty since we defined a default base dir
- Select `AWS S3 (Compatible)` as storage and then set `Bucket`, `Region` and optionally a `Key Prefix` if you want to restrict the user to a specific virtual folder in the bucket. The specified virtual folder does not need to be pre-created. You can leave `Access Key` and `Access Secret` empty since we defined global credentials for the `sftpgo` user and we use this system user to run the SFTPGo service.

You are done! Now you can connect to you SFTPGo instance using any compatible `sftp` client on port `2022`.

You can mix S3 users with local users but please be aware that we are running the service as the unprivileged `sftpgo` system user so if you set storage as `local` for an SFTPGo virtual user then the home directory for this user must be owned by the `sftpgo` system user. If you don't specify an home directory the default will be `/srv/sftpgo/data/<username>` which should be appropriate.
