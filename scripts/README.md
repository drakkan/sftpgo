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
 - `-t`, `--no-color`, disable color highligth for JSON responses. You need python pygments module 1.5 or above for this to work. Default disabled if pygments is found, enabled if not found. Please read the note at the end of this doc for colors in Windows command prompt.

For each subcommand `--help` shows the available arguments, try for example:

```python sftpgo_api_cli.py add_user --help```

Let's see a sample usage for each REST API.

### Add user

Command:

```
python sftpgo_api_cli.py add-user test_username --password "test_pwd" --home-dir="/tmp/test_home_dir" --uid 33 --gid 1000 --max-sessions 2 --quota-size 0 --quota-files 3 --permissions "list" "download" "upload" "delete" "rename" "create_dirs" --upload-bandwidth 100 --download-bandwidth 60
```

Output:

```json
{
  "id": 5140,
  "username": "test_username",
  "home_dir": "/tmp/test_home_dir",
  "uid": 33,
  "gid": 1000,
  "max_sessions": 2,
  "quota_size": 0,
  "quota_files": 3,
  "permissions": [
    "list",
    "download",
    "upload",
    "delete",
    "rename",
    "create_dirs"
  ],
  "used_quota_size": 0,
  "used_quota_files": 0,
  "last_quota_update": 0,
  "upload_bandwidth": 100,
  "download_bandwidth": 60
}
```

### Update user

Command:

```
python sftpgo_api_cli.py update-user 5140 test_username --password "test_pwd" --home-dir="/tmp/test_home_dir" --uid 0 --gid 33 --max-sessions 3 --quota-size 0 --quota-files 4 --permissions "*" --upload-bandwidth 90 --download-bandwidth 80
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
python sftpgo_api_cli.py get-user-by-id 5140
```

Output:

```json
{
  "id": 5140,
  "username": "test_username",
  "home_dir": "/tmp/test_home_dir",
  "uid": 0,
  "gid": 33,
  "max_sessions": 2,
  "quota_size": 0,
  "quota_files": 4,
  "permissions": [
    "*"
  ],
  "used_quota_size": 0,
  "used_quota_files": 0,
  "last_quota_update": 0,
  "upload_bandwidth": 90,
  "download_bandwidth": 80
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
    "id": 5140,
    "username": "test_username",
    "home_dir": "/tmp/test_home_dir",
    "uid": 0,
    "gid": 33,
    "max_sessions": 2,
    "quota_size": 0,
    "quota_files": 4,
    "permissions": [
      "*"
    ],
    "used_quota_size": 0,
    "used_quota_files": 0,
    "last_quota_update": 0,
    "upload_bandwidth": 90,
    "download_bandwidth": 80
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
    "username": "test_username",
    "connection_id": "76a11b22260ee4249328df28bef34dc64c70f7c097db52159fc24049eeb0e32c",
    "client_version": "SSH-2.0-OpenSSH_8.0",
    "remote_address": "127.0.0.1:41622",
    "connection_time": 1564696137971,
    "last_activity": 1564696159605,
    "protocol": "SFTP",
    "active_transfers": [
      {
        "operation_type": "upload",
        "path": "/test_upload.gz",
        "start_time": 1564696149783,
        "size": 1146880,
        "last_activity": 1564696159605
      }
    ]
  }
]
```

### Close connection

Command:

```
python sftpgo_api_cli.py close-connection 76a11b22260ee4249328df28bef34dc64c70f7c097db52159fc24049eeb0e32c
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
python sftpgo_api_cli.py delete-user 5140
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
  "version": "0.9.0-dev",
  "build_date": "2019-08-08T08:11:34Z",
  "commit_hash": "4f4489d-dirty"
}
```

### Colors highlight for Windows command prompt

If your Windows command prompt does not recognize ANSI/VT100 escape sequences you can download [ANSICON](https://github.com/adoxa/ansicon "ANSICON") extract proper files depending on your Windows OS, and install them using `ansicon -i`.
Thats all. From now on, your Windows command prompt will be aware of ANSI colors.