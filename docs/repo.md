# SFTPGo repositories

These repositories are available through Oregon State University's free mirroring service. Special thanks to Lance Albertson, Director of the Oregon State University Open Source Lab, who helped me with the initial setup.

## APT repo

Supported distributions:

- Debian 10 "buster"
- Debian 11 "bullseye"

Import the public key used by the package management system:

```shell
curl -sS https://ftp.osuosl.org/pub/sftpgo/apt/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/sftpgo-archive-keyring.gpg
```

If you receive an error indicating that `gnupg` is not installed, you can install it using the following command:

```shell
sudo apt install gnupg
```

Create the SFTPGo source list file:

```shell
CODENAME=`lsb_release -c -s`
echo "deb [signed-by=/usr/share/keyrings/sftpgo-archive-keyring.gpg] https://ftp.osuosl.org/pub/sftpgo/apt ${CODENAME} main" | sudo tee /etc/apt/sources.list.d/sftpgo.list
```

Reload the package database and install SFTPGo:

```shell
sudo apt update
sudo apt install sftpgo
```

## YUM repo

The YUM repository supports generic Red Hat based distributions.

Create the SFTPGo repository:

```shell
ARCH=`uname -m`
curl -sS https://ftp.osuosl.org/pub/sftpgo/yum/${ARCH}/sftpgo.repo | sudo tee /etc/yum.repos.d/sftpgo.repo
```

Reload the package database and install SFTPGo:

```shell
sudo yum update
sudo yum install sftpgo
```

Start the SFTPGo service and enable it to start at system boot:

```shell
sudo systemctl start sftpgo
sudo systemctl enable sftpgo
```
