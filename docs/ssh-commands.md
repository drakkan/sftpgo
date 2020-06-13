# SSH commands

Some SSH commands are implemented directly inside SFTPGo, while for other commands we use system commands that need to be installed and in your system's `PATH`. For system commands we have no direct control on file creation/deletion and so we cannot support virtual folders, cloud storage filesystem, such as S3, and quota check is suboptimal. If quota is enabled, the number of files is checked at the command start and not while new files are created. The allowed size is calculated as the difference between the max quota and the used one, and it is checked against the bytes transferred via SSH. The command is aborted if it uploads more bytes than the remaining allowed size calculated at the command start. Anyway, we see the bytes that the remote command sends to the local command via SSH. These bytes contain both protocol commands and files, and so the size of the files is different from the size trasferred via SSH: for example, a command can send compressed files, or a protocol command (few bytes) could delete a big file. To mitigate this issue, quotas are recalculated at the command end with a full home directory scan. This could be heavy for big directories. If you need system commands and quotas you could consider disabling quota restrictions and periodically update quota usage yourself using the REST API.

We support the following SSH commands:

- `scp`, we have our own SCP implementation since we can't rely on `scp` system command to proper handle quotas, user's home dir restrictions, cloud storage providers and virtual folders. SCP between two remote hosts is supported using the `-3` scp option.
- `md5sum`, `sha1sum`, `sha256sum`, `sha384sum`, `sha512sum`. Useful to check message digests for uploaded files. These commands are implemented inside SFTPGo so they work even if the matching system commands are not available, for example, on Windows.
- `cd`, `pwd`. Some SFTP clients do not support the SFTP SSH_FXP_REALPATH packet type, so they use `cd` and `pwd` SSH commands to get the initial directory. Currently `cd` does nothing and `pwd` always returns the `/` path.
- `git-receive-pack`, `git-upload-pack`, `git-upload-archive`. These commands enable support for Git repositories over SSH. They need to be installed and in your system's `PATH`. Git commands are not allowed inside virtual folders or inside directories with file extensions filters.
- `rsync`. The `rsync` command needs to be installed and in your system's `PATH`. We cannot avoid that rsync creates symlinks, so if the user has the permission to create symlinks, we add the option `--safe-links` to the received rsync command if it is not already set. This should prevent creating symlinks that point outside the home dir. If the user cannot create symlinks, we add the option `--munge-links` if it is not already set. This should make symlinks unusable (but manually recoverable). The `rsync` command interacts with the filesystem directly and it is not aware of virtual folders and file extensions filters, so it will be automatically disabled for users with these features enabled.
- `sftpgo-copy`. This is a builtin copy implementation. It allows server side copy for files and directories. The first argument is the source file/directory and the second one is the destination file/directory, for example `sftpgo-copy <src> <dst>`. The command will fail if the destination directory exists. Copy for directories spanning virtual folders is not supported.
- `sftpgo-remove`. This is a builtin remove implementation. It allows to remove files and directory recursively. The first argument is the file/directory to remove, for example `sftpgo-remove <dst>`.

The following SSH commands are enabled by default:

- `md5sum`
- `sha1sum`
- `cd`
- `pwd`
- `scp`