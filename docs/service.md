# Running SFTPGo as a service

Download a binary SFTPGo [release](https://github.com/drakkan/sftpgo/releases) or a build artifact for the [latest commit](https://github.com/drakkan/sftpgo/actions) or build SFTPGo yourself.

Run the following instructions from the directory that contains the sftpgo binary and the accompanying files.

## Linux

The easiest way to run SFTPGo as a service is to download and install the pre-compiled deb/rpm package or use one of the Arch Linux PKGBUILDs we maintain.

This section describes the procedure to use if you prefer to build SFTPGo yourself or if you want to download and configure a pre-built release as tar.

A `systemd` sample [service](../init/sftpgo.service "systemd service") can be found inside the source tree.

Here are some basic instructions to run SFTPGo as service using a dedicated `sftpgo` system account.

Please run the following commands from the directory where you downloaded/compiled SFTPGo:

```bash
# create the sftpgo user and group
sudo groupadd --system sftpgo
sudo useradd --system \
  --gid sftpgo \
  --no-create-home \
  --home-dir /var/lib/sftpgo \
  --shell /usr/sbin/nologin \
  --comment "SFTPGo user" \
  sftpgo
# create the required directories
sudo mkdir -p /etc/sftpgo \
  /var/lib/sftpgo \
  /usr/share/sftpgo

# install the sftpgo executable
sudo install -Dm755 sftpgo /usr/bin/sftpgo
# install the default configuration file, edit it if required
sudo install -Dm644 sftpgo.json /etc/sftpgo/
# override some configuration keys using environment variables
sudo sh -c 'echo "SFTPGO_HTTPD__TEMPLATES_PATH=/usr/share/sftpgo/templates" > /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_HTTPD__STATIC_FILES_PATH=/usr/share/sftpgo/static" >> /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_HTTPD__OPENAPI_PATH=/usr/share/sftpgo/openapi" >> /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_HTTPD__BACKUPS_PATH=/var/lib/sftpgo/backups" >> /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_DATA_PROVIDER__CREDENTIALS_PATH=/var/lib/sftpgo/credentials" >> /etc/sftpgo/sftpgo.env'
# if you use a file based data provider such as sqlite or bolt consider to set the database path too, for example:
#sudo sh -c 'echo "SFTPGO_DATA_PROVIDER__NAME=/var/lib/sftpgo/sftpgo.db" >> /etc/sftpgo/sftpgo.env'
# also set the provider's PATH as env var to get initprovider to work with SQLite provider:
#export SFTPGO_DATA_PROVIDER__NAME=/var/lib/sftpgo/sftpgo.db
# install static files and templates for the web UI
sudo cp -r static templates openapi /usr/share/sftpgo/
# set files and directory permissions
sudo chown -R sftpgo:sftpgo /etc/sftpgo /var/lib/sftpgo
sudo chmod 750 /etc/sftpgo /var/lib/sftpgo
sudo chmod 640 /etc/sftpgo/sftpgo.json /etc/sftpgo/sftpgo.env
# initialize the configured data provider
# if you want to use MySQL or PostgreSQL you need to create the configured database before running the initprovider command
sudo -E su - sftpgo -m -s /bin/bash -c 'sftpgo initprovider -c /etc/sftpgo'
# install the systemd service
sudo install -Dm644 init/sftpgo.service /etc/systemd/system
# start the service
sudo systemctl start sftpgo
# verify that the service is started
sudo systemctl status sftpgo
# automatically start sftpgo on boot
sudo systemctl enable sftpgo
# optional, create shell completion script, for example for bash
sudo sh -c '/usr/bin/sftpgo gen completion bash > /usr/share/bash-completion/completions/sftpgo'
# optional, create man pages
sudo /usr/bin/sftpgo gen man -d /usr/share/man/man1
```

## macOS

For macOS, a `launchd` sample [service](../init/com.github.drakkan.sftpgo.plist "launchd plist") can be found inside the source tree. The `launchd` plist assumes that SFTPGo has `/usr/local/opt/sftpgo` as base directory.

Here are some basic instructions to run SFTPGo as service, please run the following commands from the directory where you downloaded SFTPGo:

```bash
# create the required directories
sudo mkdir -p /usr/local/opt/sftpgo/init \
  /usr/local/opt/sftpgo/var/lib \
  /usr/local/opt/sftpgo/usr/share \
  /usr/local/opt/sftpgo/var/log \
  /usr/local/opt/sftpgo/etc \
  /usr/local/opt/sftpgo/bin

# install sftpgo executable
sudo cp sftpgo /usr/local/opt/sftpgo/bin/
# install the launchd service
sudo cp init/com.github.drakkan.sftpgo.plist /usr/local/opt/sftpgo/init/
sudo chown root:wheel /usr/local/opt/sftpgo/init/com.github.drakkan.sftpgo.plist
# install the default configuration file, edit it if required
sudo cp sftpgo.json /usr/local/opt/sftpgo/etc/
# install static files and templates for the web UI
sudo cp -r static templates openapi /usr/local/opt/sftpgo/usr/share/
# initialize the configured data provider
# if you want to use MySQL or PostgreSQL you need to create the configured database before running the initprovider command
sudo /usr/local/opt/sftpgo/bin/sftpgo initprovider -c /usr/local/opt/sftpgo/etc/
# add sftpgo to the launch daemons
sudo ln -s /usr/local/opt/sftpgo/init/com.github.drakkan.sftpgo.plist /Library/LaunchDaemons/com.github.drakkan.sftpgo.plist
# start the service and enable it to start on boot
sudo launchctl load -w /Library/LaunchDaemons/com.github.drakkan.sftpgo.plist
# verify that the service is started
sudo launchctl list com.github.drakkan.sftpgo
```

## Windows

On Windows, you can register SFTPGo as Windows Service. Take a look at the CLI usage to learn how to do this:

```powershell
PS> sftpgo.exe service --help
Manage SFTPGo Windows Service

Usage:
  sftpgo service [command]

Available Commands:
  install     Install SFTPGo as Windows Service
  reload      Reload the SFTPGo Windows Service sending a "paramchange" request
  rotatelogs  Signal to the running service to rotate the logs
  start       Start SFTPGo Windows Service
  status      Retrieve the status for the SFTPGo Windows Service
  stop        Stop SFTPGo Windows Service
  uninstall   Uninstall SFTPGo Windows Service

Flags:
  -h, --help   help for service

Use "sftpgo service [command] --help" for more information about a command.
```

The `install` subcommand accepts the same flags that are valid for `serve`.

After installing as a Windows Service, please remember to allow network access to the SFTPGo executable using something like this:

```powershell
PS> netsh advfirewall firewall add rule name="SFTPGo Service" dir=in action=allow program="C:\Program Files\SFTPGo\sftpgo.exe"
```

Or through the Windows Firewall GUI.

The Windows installer will register the service and allow network access for it automatically.
