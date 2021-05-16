# Data Backup

The `backup` example script shows how to use the SFTPGo REST API to backup your data.

The script is written in Python and has the following requirements:

- python3 or python2
- python [Requests](https://requests.readthedocs.io/en/master/) module

The provided example tries to connect to an SFTPGo instance running on `127.0.0.1:8080` using the following credentials:

- username: `admin`
- password: `password`

and, if you execute it daily, it saves a different backup file for each day of the week. The backups will be saved within the configured `backups_path`.

Please edit the script according to your needs.
