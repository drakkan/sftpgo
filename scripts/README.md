## REST API CLI client

`sftpgo_api_cli.py` is a very simple command line client for `SFTPGo` REST API written in python.

It has the following requirements:

- python3 or python2
- python [Requests](https://2.python-requests.org/en/master/ "Requests") module
- Optionally, if the python module [Pygments](http://pygments.org/ "Pygments") 1.5 or above is installed, the JSON responses will be highlighted with colors.

You can see the usage with the following command:

```
python sftpgo_api_cli.py --help
```

and

```
python sftpgo_api_cli.py [sub-command] --help
```

Basically there is a sub command for each REST API and the following global arguments:

 - `-d`, `--debug`, default disabled, print useful debug info.
 - `-b`, `--base-url`, default `http://127.0.0.1:8080`. Base URL for SFTPGo REST API
 - `-a`, `--auth-type`, HTTP auth type. Supported HTTP auth type are `basic` and `digest`. Default none
 - `-u`, `--auth-user`, user for HTTP authentication
 - `-p`, `--auth-password`, password for HTTP authentication
 - `-i`, `--insecure`, enable to ignore verifying the SSL certificate. Default disabled
 - `-t`, `--no-color`, disable color highligth for JSON responses. You need python pygments module 1.5 or above for this to work. Default disabled if pygments is found and you aren't on Windows, otherwise enabled.
 - `-c`, `--color`, enable color highligth for JSON responses. You need python pygments module 1.5 or above for this to work. Default enabled if `pygments` is found and you aren't on Windows, otherwise disabled. Please read the note at the end of this doc for colors in Windows command prompt.

For each subcommand `--help` shows the available arguments, try for example:

```python sftpgo_api_cli.py add_user --help```

Additionally it can convert users to the SFTPGo format from some supported users stores

Let's see a sample usage for each REST API.

### Add user

Command:

```
python sftpgo_api_cli.py add-user test_username --password "test_pwd" --home-dir="/tmp/test_home_dir" --uid 33 --gid 1000 --max-sessions 2 --quota-size 0 --quota-files 3 --permissions "list" "download" "upload" "delete" "rename" "create_dirs" "overwrite" --subdirs-permissions "/dir1:list,download" "/dir2:*" --upload-bandwidth 100 --download-bandwidth 60 --status 0 --expiration-date 2019-01-01 --allowed-ip "192.168.1.1/32" --fs S3 --s3-bucket test --s3-region eu-west-1 --s3-access-key accesskey --s3-access-secret secret --s3-endpoint "http://127.0.0.1:9000" --s3-storage-class Standard
```

Output:

```json
{
  "download_bandwidth": 60,
  "expiration_date": 1546297200000,
  "filesystem": {
    "provider": 1,
    "s3config": {
      "access_key": "accesskey",
      "access_secret": "$aes$6c088ba12b0b261247c8cf331c46d9260b8e58002957d89ad1c0495e3af665cd0227",
      "bucket": "test",
      "endpoint": "http://127.0.0.1:9000",
      "region": "eu-west-1",
      "storage_class": "Standard"
    }
  },
  "filters": {
    "allowed_ip": [
      "192.168.1.1/32"
    ],
    "denied_ip": []
  },
  "gid": 1000,
  "home_dir": "/tmp/test_home_dir",
  "id": 9576,
  "last_login": 0,
  "last_quota_update": 0,
  "max_sessions": 2,
  "permissions": {
    "/": [
      "list",
      "download",
      "upload",
      "delete",
      "rename",
      "create_dirs",
      "overwrite"
    ],
    "/dir1": [
      "list",
      "download"
    ],
    "/dir2": [
      "*"
    ]
  },
  "quota_files": 3,
  "quota_size": 0,
  "status": 0,
  "uid": 33,
  "upload_bandwidth": 100,
  "used_quota_files": 0,
  "used_quota_size": 0,
  "username": "test_username"
}
```

### Update user

Command:

```
python sftpgo_api_cli.py update-user 9576 test_username --password "test_pwd" --home-dir="/tmp/test_home_dir" --uid 0 --gid 33 --max-sessions 3 --quota-size 0 --quota-files 4 --permissions "*" --subdirs-permissions "/dir1:list,download,create_symlinks" --upload-bandwidth 90 --download-bandwidth 80 --status 1 --expiration-date "" --allowed-ip "" --denied-ip "192.168.1.0/24" --fs local
```

Output:

```json
{
  "error": "",
  "message": "User updated",
  "status": 200
}
```

### Get user by id

Command:

```
python sftpgo_api_cli.py get-user-by-id 9576
```

Output:

```json
{
  "download_bandwidth": 80,
  "expiration_date": 0,
  "filesystem": {
    "provider": 0,
    "s3config": {}
  },
  "filters": {
    "allowed_ip": [],
    "denied_ip": [
      "192.168.1.0/24"
    ]
  },
  "gid": 33,
  "home_dir": "/tmp/test_home_dir",
  "id": 9576,
  "last_login": 0,
  "last_quota_update": 0,
  "max_sessions": 3,
  "permissions": {
    "/": [
      "*"
    ],
    "/dir1": [
      "list",
      "download",
      "create_symlinks"
    ]
  },
  "quota_files": 4,
  "quota_size": 0,
  "status": 1,
  "uid": 0,
  "upload_bandwidth": 90,
  "used_quota_files": 0,
  "used_quota_size": 0,
  "username": "test_username"
}
```

### Get users

Command:

```
python sftpgo_api_cli.py get-users --limit 1 --offset 0 --username test_username --order DESC
```

Output:

```json
[
  {
    "download_bandwidth": 80,
    "expiration_date": 0,
    "filesystem": {
      "provider": 0,
      "s3config": {}
    },
    "filters": {
      "allowed_ip": [],
      "denied_ip": [
        "192.168.1.0/24"
      ]
    },
    "gid": 33,
    "home_dir": "/tmp/test_home_dir",
    "id": 9576,
    "last_login": 0,
    "last_quota_update": 0,
    "max_sessions": 3,
    "permissions": {
      "/": [
        "*"
      ],
      "/dir1": [
        "list",
        "download",
        "create_symlinks"
      ]
    },
    "quota_files": 4,
    "quota_size": 0,
    "status": 1,
    "uid": 0,
    "upload_bandwidth": 90,
    "used_quota_files": 0,
    "used_quota_size": 0,
    "username": "test_username"
  }
]
```

### Get active connections

Command:

```
python sftpgo_api_cli.py get-connections
```

Output:

```json
[
  {
    "active_transfers": [
      {
        "last_activity": 1577197485561,
        "operation_type": "upload",
        "path": "/test_upload.tar.gz",
        "size": 1540096,
        "start_time": 1577197471372
      }
    ],
    "client_version": "SSH-2.0-OpenSSH_8.1",
    "connection_id": "f82cfec6a391ad673edd4ae9a144f32ccb59456139f8e1185b070134fffbab7c",
    "connection_time": 1577197433003,
    "last_activity": 1577197485561,
    "protocol": "SFTP",
    "remote_address": "127.0.0.1:43714",
    "ssh_command": "",
    "username": "test_username"
  }
]
```

### Close connection

Command:

```
python sftpgo_api_cli.py close-connection f82cfec6a391ad673edd4ae9a144f32ccb59456139f8e1185b070134fffbab7c
```

Output:

```json
{
  "error": "",
  "message": "Connection closed",
  "status": 200
}
```

### Get quota scans

Command:

```
python sftpgo_api_cli.py get-quota-scans
```

### Start quota scan

Command:

```
python sftpgo_api_cli.py start-quota-scan test_username
```

Output:

```json
{
  "status": 201,
  "message": "Scan started",
  "error": ""
}
```

### Delete user

Command:

```
python sftpgo_api_cli.py delete-user 9576
```

Output:

```json
{
  "error": "",
  "message": "User deleted",
  "status": 200
}
```

### Get version

Command:

```
python sftpgo_api_cli.py get-version
```

Output:

```json
{
  "build_date": "2019-12-24T14:17:47Z",
  "commit_hash": "f8fd5c0-dirty",
  "version": "0.9.4-dev"
}
```

### Get provider status

Command:

```
python sftpgo_api_cli.py get-provider-status
```

Output:

```json
{
  "error": "",
  "message": "Alive",
  "status": 200
}
```

### Backup data

Command:

```
python sftpgo_api_cli.py dumpdata backup.json
```

Output:

```json
{
  "error": "",
  "message": "Data saved",
  "status": 200
}
```

### Restore data

Command:

```
python sftpgo_api_cli.py loaddata /app/data/backups/backup.json --scan-quota 2
```

Output:

```json
{
  "error": "",
  "message": "Data restored",
  "status": 200
}
```

### Convert users from other stores

You can convert users to the SFTPGo format from the following users stores:

- Linux users stored in `shadow`/`passwd` files
- Pure-FTPd virtual users generated using `pure-pw` CLI
- ProFTPD users generated using `ftpasswd` CLI

For details give a look at the `convert-users` subcommand usage:

```
python sftpgo_api_cli.py convert-users --help
```

Let's see some examples:

```
python sftpgo_api_cli.py convert-users "" unix-passwd unix_users.json --min-uid 500 --force-uid 1000 --force-gid 1000
```

```
python sftpgo_api_cli.py convert-users pureftpd.passwd pure-ftpd pure_users.json --usernames "user1" "user2"
```

```
python sftpgo_api_cli.py convert-users proftpd.passwd proftpd pro_users.json
```

The json file generated using the `convert-users` subcommand can be used as input for the `loaddata` subcommand.

Please note that when importing Linux/Unix users the input file is not required: `/etc/passwd` and `/etc/shadow` are automatically parsed. `/etc/shadow` read permission is is typically granted to the `root` user, so you need to execute the `convert-users` subcommand as `root`.

### Colors highlight for Windows command prompt

If your Windows command prompt does not recognize ANSI/VT100 escape sequences you can download [ANSICON](https://github.com/adoxa/ansicon "ANSICON") extract proper files depending on your Windows OS, and install them using `ansicon -i`.
Thats all. From now on, your Windows command prompt will be aware of ANSI colors.