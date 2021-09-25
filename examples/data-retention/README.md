# File retention policies

The `checkretention` example script shows how to use the SFTPGo REST API to manage data retention.

:warning: Deleting files is an irreversible action, please make sure you fully understand what you are doing before using this feature, you may have users with overlapping home directories or virtual folders shared between multiple users, it is relatively easy to inadvertently delete files you need.

The example shows how to setup a really simple retention policy, for each user it sends this request:

```json
[
  {
    "path": "/",
    "retention": 168,
    "delete_empty_dirs": true,
    "ignore_user_permissions": false
  }
]
```

so alls files with modification time older than 168 hours (7 days) will be deleted. Empty directories will be removed and the check will respect user's permissions, so if the user cannot delete a file/folder it will be skipped.

You can define different retention policies per-user and per-folder and you can exclude a folder setting the retention to `0`.

You can use this script as a starting point, please edit it according to your needs.

The script is written in Python and has the following requirements:

- python3 or python2
- python [Requests](https://requests.readthedocs.io/en/master/) module

The provided example tries to connect to an SFTPGo instance running on `127.0.0.1:8080` using the following credentials:

- username: `admin`
- password: `password`
