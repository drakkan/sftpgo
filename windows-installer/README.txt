SFTPGo allows you to securely share your files over SFTP and optionally over HTTP/S, FTP/S and WebDAV as well.
Several storage backends are supported: local filesystem, encrypted local filesystem, S3 (compatible) Object Storage,
Google Cloud Storage, Azure Blob Storage, other SFTP servers.

If this is your first installation please open the web administration panel:

http://localhost:8080/web/admin

and complete the initial setup.

The SFTP service is available, by default, on port 2022.

If the SFTPGo service does not start, make sure that TCP ports 2022 and 8080 are not used by other services
or change the SFTPGo configuration to suit your needs.

Default data location:

C:\ProgramData\SFTPGo

Configuration file location:

C:\ProgramData\SFTPGo\sftpgo.json

Getting started guide:

https://github.com/drakkan/sftpgo/blob/main/docs/howto/getting-started.md

Step-to-step tutorials:

https://github.com/drakkan/sftpgo/tree/main/docs/howto

Source code and documentation:

https://github.com/drakkan/sftpgo

If you find a bug please open an issue:

https://github.com/drakkan/sftpgo/issues

If you want to suggest a new feature or have a question, please start a new discussion:

https://github.com/drakkan/sftpgo/discussions
