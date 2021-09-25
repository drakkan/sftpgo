# Update user quota

The `scanuserquota` example script shows how to use the SFTPGo REST API to update the users' quota.

The stored quota may be incorrect for several reasons, such as an unexpected shutdown while uploading files, temporary provider failures, files copied outside of SFTPGo, and so on.

A quota scan updates the number of files and their total size for the specified user and the virtual folders, if any, included in his quota.

If you want to track quotas, a scheduled quota scan is recommended. You can use this example as a starting point.

The script is written in Python and has the following requirements:

- python3 or python2
- python [Requests](https://requests.readthedocs.io/en/master/) module

The provided example tries to connect to an SFTPGo instance running on `127.0.0.1:8080` using the following credentials:

- username: `admin`
- password: `password`

Please edit the script according to your needs.
