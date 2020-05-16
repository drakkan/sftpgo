# Running SFTPGo as a service

## Linux

For Linux, a `systemd` sample [service](../init/sftpgo.service "systemd service") can be found inside the source tree.

Here are some basic instructions to run SFTPGo as service, please run the following commands from the directory where you downloaded SFTPGo:

```bash
# create the required directories
sudo mkdir -p /etc/sftpgo \
  /var/lib/sftpgo

# install sftpgo executable
sudo install -Dm755 sftpgo /usr/bin/sftpgo
# install the default configuration file, edit it if required
sudo install -Dm644 sftpgo.json /etc/sftpgo/
# override some configuration keys using environment variables
sudo sh -c 'echo "SFTPGO_HTTPD__TEMPLATES_PATH=/var/lib/sftpgo/templates" > /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_HTTPD__STATIC_FILES_PATH=/var/lib/sftpgo/static" >> /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_HTTPD__BACKUPS_PATH=/var/lib/sftpgo/backups" >> /etc/sftpgo/sftpgo.env'
sudo sh -c 'echo "SFTPGO_DATA_PROVIDER__CREDENTIALS_PATH=/var/lib/sftpgo/credentials" >> /etc/sftpgo/sftpgo.env'
# install static files and templates for the web UI
sudo cp -r static templates /var/lib/sftpgo/
# initialize the configured data provider
# if you want to use MySQL or PostgreSQL you need to create the configured database before running the initprovider command
sudo /usr/bin/sftpgo initprovider -c /etc/sftpgo/
# install the systemd service
sudo install -Dm644 init/sftpgo.service /etc/systemd/system
# start the service
sudo systemctl start sftpgo
# verify that the service is started
sudo systemctl status sftpgo
# automatically start sftpgo on boot
sudo systemctl enable sftpgo
# optional, install the REST API CLI. It requires python-requests to run
sudo install -Dm755 examples/rest-api-cli/sftpgo_api_cli.py /usr/bin/sftpgo_api_cli
```

## macOS

For macOS, a `launchd` sample [service](../init/com.github.drakkan.sftpgo.plist "launchd plist") can be found inside the source tree. The `launchd` plist assumes that SFTPGo has `/usr/local/opt/sftpgo` as base directory.

Here are some basic instructions to run SFTPGo as service, please run the following commands from the directory where you downloaded SFTPGo:

```bash
# create the required directories
sudo mkdir -p /usr/local/opt/sftpgo/init \
  /usr/local/opt/sftpgo/var/lib \
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
sudo cp -r static templates /usr/local/opt/sftpgo/var/lib/
# initialize the configured data provider
# if you want to use MySQL or PostgreSQL you need to create the configured database before running the initprovider command
sudo /usr/local/opt/sftpgo/bin/sftpgo initprovider -c /usr/local/opt/sftpgo/etc/
# add sftpgo to the launch daemons
sudo ln -s /usr/local/opt/sftpgo/init/com.github.drakkan.sftpgo.plist /Library/LaunchDaemons/com.github.drakkan.sftpgo.plist
# start the service and enable it to start on boot
sudo launchctl load -w /Library/LaunchDaemons/com.github.drakkan.sftpgo.plist
# verify that the service is started
sudo launchctl list com.github.drakkan.sftpgo
# optional, install the REST API CLI. It requires python-requests to run, this python module is not installed by default
sudo cp examples/rest-api-cli/sftpgo_api_cli.py /usr/local/opt/sftpgo/bin/
```

## Windows

On Windows, you can register SFTPGo as Windows Service. Take a look at the CLI usage to learn how to do this:

```powershell
PS> sftpgo.exe service --help
Install, Uninstall, Start, Stop, Reload and retrieve status for SFTPGo Windows Service

Usage:
  sftpgo service [command]

Available Commands:
  install     Install SFTPGo as Windows Service
  reload      Reload the SFTPGo Windows Service sending a `paramchange` request
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

(Or through the Windows Firewall GUI.)
