# Portable mode

SFTPGo allows to share a single directory on demand using the `portable` subcommand:

```
sftpgo portable --help
To serve the current working directory with auto generated credentials simply use:

sftpgo portable

Please take a look at the usage below to customize the serving parameters

Usage:
  sftpgo portable [flags]

Flags:
  -C, --advertise-credentials           If the SFTP service is advertised via multicast DNS, this flag allows to put username/password inside the advertised TXT record
  -S, --advertise-service               Advertise SFTP service using multicast DNS (default true)
  -d, --directory string                Path to the directory to serve. This can be an absolute path or a path relative to the current directory (default ".")
  -f, --fs-provider int                 0 means local filesystem, 1 Amazon S3 compatible, 2 Google Cloud Storage
      --gcs-automatic-credentials int   0 means explicit credentials using a JSON credentials file, 1 automatic (default 1)
      --gcs-bucket string
      --gcs-credentials-file string     Google Cloud Storage JSON credentials file
      --gcs-key-prefix string           Allows to restrict access to the virtual folder identified by this prefix and its contents
      --gcs-storage-class string
  -h, --help                            help for portable
  -l, --log-file-path string            Leave empty to disable logging
  -p, --password string                 Leave empty to use an auto generated value
  -g, --permissions strings             User's permissions. "*" means any permission (default [list,download])
  -k, --public-key strings
      --s3-access-key string
      --s3-access-secret string
      --s3-bucket string
      --s3-endpoint string
      --s3-key-prefix string            Allows to restrict access to the virtual folder identified by this prefix and its contents
      --s3-region string
      --s3-storage-class string
  -s, --sftpd-port int                  0 means a random non privileged port
  -c, --ssh-commands strings            SSH commands to enable. "*" means any supported SSH command including scp (default [md5sum,sha1sum,cd,pwd])
  -u, --username string                 Leave empty to use an auto generated value
```

In portable mode, SFTPGo can advertise the SFTP service and, optionally, the credentials via multicast DNS, so there is a standard way to discover the service and to automatically connect to it.

Here is an example of the advertised service including credentials as seen using `avahi-browse`:

```
= enp0s31f6 IPv4 SFTPGo portable 53705                         SFTP File Transfer   local
   hostname = [p1.local]
   address = [192.168.1.230]
   port = [53705]
   txt = ["password=EWOo6pJe" "user=user" "version=0.9.3-dev-b409523-dirty-2019-10-26T13:43:32Z"]
```

