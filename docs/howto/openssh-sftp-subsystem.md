# SFTPGo as OpenSSH's SFTP subsystem

This tutorial shows how to run SFTPGo as OpenSSH's SFTP subsystem and still use its advanced features.

Please note that when running in SFTP subsystem mode some SFTPGo features are not available, for example SFTPGo cannot limit the concurrent connnections or user sessions, restrict available ciphers etc. In this mode OpenSSH accepts the network connection, handles the SSH handshake and user authentication and then executes a separate SFTPGo process for each SFTP connection.

## Preliminary Note

Before proceeding further you need to have a basic minimal installation of Ubuntu 20.04. The instructions can easily be adapted to any other Linux distribution.

## Install SFTPGo

To install SFTPGo you can use the PPA [here](https://launchpad.net/~sftpgo/+archive/ubuntu/sftpgo).

Start by adding the PPA.

```shell
sudo add-apt-repository ppa:sftpgo/sftpgo
sudo apt update
```

Next install SFTPGo.

```shell
sudo apt install sftpgo
```

After installation SFTPGo should already be running and configured to start automatically at boot, check its status using the following command.

```shell
systemctl status sftpgo
```

We don't want to run SFTPGo as service, so let's stop and disable it.

```shell
sudo systemctl disable sftpgo
sudo systemctl stop sftpgo
```

## Configure OpenSSH to use SFTPGo as SFTP subsystem

We have several configuration options. Let's examine them in details in the following sections.

### Chroot any existing OpenSSH user within their home directory

Open the OpenSSH configuration file `/etc/ssh/sshd_config` find the following section:

```shell
# override default of no subsystems
Subsystem sftp /usr/lib/openssh/sftp-server
```

and change it as follow.

```shell
# override default of no subsystems
#Subsystem sftp /usr/lib/openssh/sftp-server
Subsystem  sftp /usr/bin/sftpgo startsubsys -j
```

The `-j` option instructs SFTPGo to write logs to `journald`. If unset the logs will be written to stdout.

Restart OpenSSH to apply the changes.

```shell
sudo systemctl restart sshd
```

Now try to login via SFTP with an existing OpenSSH user, it will work and you will not be able to escape the user's home directory.

### Change home dir, set virtual permissions and other SFTPGo specific features

The current setup is pretty straightforward and can also be easily achieved using OpenSSH. Can we set a different home directory or use specific SFTPGo features such as bandwidth throttling, virtual permissions and so on?

Of course we can, we need to configure SFTPGo with an appropriate configuration file and we need to map OpenSSH users to SFTPGo users.

SFTPGo stores its users within a data provider, several data providers are supported. For this use case SQLite and bolt cannot be used as OpenSSH will start multiple SFTPGo processes and it is not safe/possible to access to these data providers from multiple separate processes. So we will use the memory provider. MySQL, PostgreSQL and CockroachDB can be used too.

Any unmapped OpenSSH user will work as explained in the previous section. So you could only map specific users.

The memory provider can load users from a JSON file. Theoretically you could create the JSON file by hand, but this is quite hard. An easier way is to create users from another SFTPGo instance and then export a dump.

Then, we temporarily launch the system's SFTPGo instance.

```shell
sudo systemctl start sftpgo.service
```

We assume that we have an OpenSSH/system user named `nicola` and its home directory is `/home/nicola`, adjust the following instructions according to your configuration.

Open [http://127.0.0.1:8080/web/admin](http://127.0.0.1:8080/web) in your web browser, replacing `127.0.0.1` with the appropriate IP address if SFTPGo is not running on localhost and initialize SFTPGo. The full procedure is detailed within the [Getting Started](./getting-started.md#Initial-configuration) guide.

Now, from the SFTPGo web admin interface, create a user named `nicola` (like our OpenSSH/system user) and set his home directory to `/home/nicola/sftpdir`. You must set a password or a public key to be able to save the user, set any password it will be ignored as it is OpenSSH that authenticates users.

You can also set some virtual permissions, for example for the path `/test` allow `list` and `upload`. You can also set a quota or bandwidth limits, for example you can set `5` as quota files and `128 KB/s` as upload bandwidth.

Save the user.

From the `Maintenance` section save a backup to `/home/nicola`. You should now have the file `/home/nicola/sftpgo-backup.json`.

We can stop the SFTPGo instance now.

```shell
sudo systemctl stop sftpgo.service
```

If you check the JSON backup file, it should contain something like this.

```json
"users": [
    {
      "id": 1,
      "status": 1,
      "username": "nicola",
      "expiration_date": 0,
      "password": "$2a$10$dc.djrShrnyEdfpTEh5S2utQr2CTja1XOB2O4ZiGcvFxbrvcgu/WK",
      "home_dir": "/home/nicola/sftpdir",
      "uid": 0,
      "gid": 0,
      "max_sessions": 0,
      "quota_size": 0,
      "quota_files": 5,
      "permissions": {
        "/": [
          "*"
        ],
        "/test": [
          "list",
          "upload"
        ]
      },
      "used_quota_size": 0,
      "used_quota_files": 0,
      "last_quota_update": 0,
      "upload_bandwidth": 128,
      "download_bandwidth": 0,
      ...
```

Let's create a specific configuration directory for SFTPGo as a subsystem and copy the configuration file and the backup file there.

```shell
sudo mkdir /usr/local/etc/sftpgosubsys
sudo cp /etc/sftpgo/sftpgo.json /usr/local/etc/sftpgosubsys/
sudo chmod 644 /usr/local/etc/sftpgosubsys/sftpgo.json
sudo cp /home/nicola/sftpgo-backup.json /usr/local/etc/sftpgosubsys/
```

Open `/usr/local/etc/sftpgosubsys/sftpgo.json`, find the `data_provider` section and change it as follow.

```json
...
"data_provider": {
    "driver": "memory",
    "name": "/usr/local/etc/sftpgosubsys/sftpgo-backup.json",
...
```

Open `/etc/ssh/sshd_config` and set the following configuration.

```shell
# override default of no subsystems
#Subsystem sftp /usr/lib/openssh/sftp-server
Subsystem  sftp /usr/bin/sftpgo startsubsys -c /usr/local/etc/sftpgosubsys -j -p
```

The `-c` option specifies where to search the configuration file and the `-p` option indicates to use the home directory from the data provider (the json backup file in this case) for users defined there.

Restart OpenSSH to apply the changes.

```shell
sudo systemctl restart sshd
```

Now you can log in using the user `nicola` and verify that the new chroot directory is `/home/nicola/sftpdir`, and that the other settings are working. Eg. create a directory called `test`, you will be able to upload files but not download them.

### Configure a custom hook on file uploads

We show this feature by executing a simple bash script each time a file is uploaded.

Here is the test script.

```shell
#!/bin/bash

echo `date` "env, action: $SFTPGO_ACTION, username: $SFTPGO_ACTION_USERNAME, path: $SFTPGO_ACTION_PATH, file size: $SFTPGO_ACTION_FILE_SIZE, status: $SFTPGO_ACTION_STATUS" >> /tmp/command_sftp.log
```

It simply logs some environment variables that SFTPGo sets for the upload action. Please refer to [Custom Actions](../custom-actions.md) for more detailed info about hooks.

So copy the above script to the file `/usr/local/bin/sftpgo-action.sh` and make it executable.

```shell
sudo chmod 755 /usr/local/bin/sftpgo-action.sh
```

Open `/usr/local/etc/sftpgosubsys/sftpgo.json`, and configure the custom action as follow.

```shell
{
  "common": {
    "idle_timeout": 15,
    "upload_mode": 0,
    "actions": {
      "execute_on": ["upload"],
      "execute_sync": [],
      "hook": "/usr/local/bin/sftpgo-action.sh"
    },
...
```

Login and upload a file.

```shell
sftp nicola@127.0.0.1
nicola@127.0.0.1's password:
Connected to 127.0.0.1.
sftp> put file.txt
Uploading fle.txt to /file.txt
sftp> quit
```

Verify that the custom action is executed.

```shell
cat /tmp/command_sftp.log
Fri 30 Jul 2021 06:56:50 PM UTC env, action: upload, username: nicola, path: /home/nicola/sftpdir/file.txt, file size: 4034, status: 1
```
