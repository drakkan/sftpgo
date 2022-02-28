# Official Docker image

SFTPGo provides an official Docker image, it is available on both [Docker Hub](https://hub.docker.com/r/drakkan/sftpgo) and on [GitHub Container Registry](https://github.com/users/drakkan/packages/container/package/sftpgo).

## Supported tags and respective Dockerfile links

- [v2.2.2, v2.2, v2, latest](https://github.com/drakkan/sftpgo/blob/v2.2.2/Dockerfile)
- [v2.2.2-alpine, v2.2-alpine, v2-alpine, alpine](https://github.com/drakkan/sftpgo/blob/v2.2.2/Dockerfile.alpine)
- [v2.2.2-slim, v2.2-slim, v2-slim, slim](https://github.com/drakkan/sftpgo/blob/v2.2.2/Dockerfile)
- [v2.2.2-alpine-slim, v2.2-alpine-slim, v2-alpine-slim, alpine-slim](https://github.com/drakkan/sftpgo/blob/v2.2.2/Dockerfile.alpine)
- [v2.2.2-distroless-slim, v2.2-distroless-slim, v2-distroless-slim, distroless-slim](https://github.com/drakkan/sftpgo/blob/v2.2.2/Dockerfile.distroless)
- [edge](../Dockerfile)
- [edge-alpine](../Dockerfile.alpine)
- [edge-slim](../Dockerfile)
- [edge-alpine-slim](../Dockerfile.alpine)
- [edge-distroless-slim](../Dockerfile.distroless)

## How to use the SFTPGo image

### Start a `sftpgo` server instance

Starting a SFTPGo instance is simple:

```shell
docker run --name some-sftpgo -p 8080:8080 -p 2022:2022 -d "drakkan/sftpgo:tag"
```

... where `some-sftpgo` is the name you want to assign to your container, and `tag` is the tag specifying the SFTPGo version you want. See the list above for relevant tags.

Now visit [http://localhost:8080/web/admin](http://localhost:8080/web/admin), replacing `localhost` with the appropriate IP address if SFTPGo is not reachable on localhost, create the first admin and a new SFTPGo user. The SFTP service is available on port 2022.

If you don't want to persist any files, for example for testing purposes, you can run an SFTPGo instance like this:

```shell
docker run --rm --name some-sftpgo -p 8080:8080 -p 2022:2022 -d "drakkan/sftpgo:tag"
```

If you prefer GitHub Container Registry to Docker Hub replace `drakkan/sftpgo:tag` with `ghcr.io/drakkan/sftpgo:tag`.

### Enable FTP service

FTP is disabled by default, you can enable the FTP service by starting the SFTPGo instance in this way:

```shell
docker run --name some-sftpgo \
    -p 8080:8080 \
    -p 2022:2022 \
    -p 2121:2121 \
    -p 50000-50100:50000-50100 \
    -e SFTPGO_FTPD__BINDINGS__0__PORT=2121 \
    -e SFTPGO_FTPD__BINDINGS__0__FORCE_PASSIVE_IP=<your external ip here> \
    -d "drakkan/sftpgo:tag"
```

The FTP service is now available on port 2121 and SFTP on port 2022.

You can change the passive ports range (`50000-50100` by default) by setting the environment variables `SFTPGO_FTPD__PASSIVE_PORT_RANGE__START` and `SFTPGO_FTPD__PASSIVE_PORT_RANGE__END`.

It is recommended that you provide a certificate and key file to expose FTP over TLS. You should prefer SFTP to FTP even if you configure TLS, please don't blindly enable the old FTP protocol.

### Enable WebDAV service

WebDAV is disabled by default, you can enable the WebDAV service by starting the SFTPGo instance in this way:

```shell
docker run --name some-sftpgo \
    -p 8080:8080 \
    -p 2022:2022 \
    -p 10080:10080 \
    -e SFTPGO_WEBDAVD__BINDINGS__0__PORT=10080 \
    -d "drakkan/sftpgo:tag"
```

The WebDAV service is now available on port 10080 and SFTP on port 2022.

It is recommended that you provide a certificate and key file to expose WebDAV over https.

### Container shell access and viewing SFTPGo logs

The docker exec command allows you to run commands inside a Docker container. The following command line will give you a shell inside your `sftpgo` container:

```shell
docker exec -it some-sftpgo sh
```

The logs are available through Docker's container log:

```shell
docker logs some-sftpgo
```

**Note:** [distroless](../Dockerfile.distroless) image contains only a statically linked sftpgo binary and its minimal runtime dependencies. Shell is not available on this image.

### Where to Store Data

Important note: There are several ways to store data used by applications that run in Docker containers. We encourage users of the SFTPGo images to familiarize themselves with the options available, including:

- Let Docker manage the storage for SFTPGo data by [writing them to disk on the host system using its own internal volume management](https://docs.docker.com/engine/tutorials/dockervolumes/#adding-a-data-volume). This is the default and is easy and fairly transparent to the user. The downside is that the files may be hard to locate for tools and applications that run directly on the host system, i.e. outside containers.
- Create a data directory on the host system (outside the container) and [mount this to a directory visible from inside the container]((https://docs.docker.com/engine/tutorials/dockervolumes/#mount-a-host-directory-as-a-data-volume)). This places the SFTPGo files in a known location on the host system, and makes it easy for tools and applications on the host system to access the files. The downside is that the user needs to make sure that the directory exists, and that e.g. directory permissions and other security mechanisms on the host system are set up correctly. The SFTPGo image runs using `1000` as UID/GID by default.

The Docker documentation is a good starting point for understanding the different storage options and variations, and there are multiple blogs and forum postings that discuss and give advice in this area. We will simply show the basic procedure here for the latter option above:

1. Create a data directory on a suitable volume on your host system, e.g. `/my/own/sftpgodata`. The user with ID `1000` must be able to write to this directory. Please note that you don't need an actual user with ID `1000` on your host system: `chown -R 1000:1000 /my/own/sftpgodata` is enough even if there is no user/group with UID/GID `1000`.
2. Create a home directory for the sftpgo container user on your host system e.g. `/my/own/sftpgohome`. As with the data directory above, make sure that the user with ID `1000` can write to this directory: `chown -R 1000:1000 /my/own/sftpgohome`
3. Start your SFTPGo container like this:

```shell
docker run --name some-sftpgo \
    -p 8080:8090 \
    -p 2022:2022 \
    --mount type=bind,source=/my/own/sftpgodata,target=/srv/sftpgo \
    --mount type=bind,source=/my/own/sftpgohome,target=/var/lib/sftpgo \
    -e SFTPGO_HTTPD__BINDINGS__0__PORT=8090 \
    -d "drakkan/sftpgo:tag"
```

As you can see SFTPGo uses two main volumes:

- `/srv/sftpgo` to handle persistent data. The default home directory for SFTP/FTP/WebDAV users is `/srv/sftpgo/data/<username>`. Backups are stored in `/srv/sftpgo/backups`
- `/var/lib/sftpgo` is the home directory for the sftpgo system user defined inside the container. This is the container working directory too, host keys will be created here when using the default configuration.

If you want to get fine grained control, you can also mount `/srv/sftpgo/data` and `/srv/sftpgo/backups` as separate volumes instead of mounting `/srv/sftpgo`.

### Configuration

The runtime configuration can be customized via environment variables that you can set passing the `-e` option to the `docker run` command or inside the `environment` section if you are using [docker stack deploy](https://docs.docker.com/engine/reference/commandline/stack_deploy/) or [docker-compose](https://github.com/docker/compose).

Please take a look [here](../docs/full-configuration.md#environment-variables) to learn how to configure SFTPGo via environment variables.

Alternately you can mount your custom configuration file to `/var/lib/sftpgo` or `/var/lib/sftpgo/.config/sftpgo`.

### Loading initial data

Initial data can be loaded in the following ways:

- via the `--loaddata-from` flag or the `SFTPGO_LOADDATA_FROM` environment variable. This flag is supported for both the `serve` command (load initial data and start the service) and the `initprovider` command (initialize the provider, load initial data and exit)
- by providing a dump file to the memory provider

Please take a look [here](../docs/full-configuration.md) for more details.

### Running as an arbitrary user

The SFTPGo image runs using `1000` as UID/GID by default. If you know the permissions of your data and/or configuration directory are already set appropriately or you have need of running SFTPGo with a specific UID/GID, it is possible to invoke this image with `--user` set to any value (other than `root/0`) in order to achieve the desired access/configuration:

```shell
$ ls -lnd data
drwxr-xr-x 2 1100 1100 6  7 nov 09.09 data
$ ls -lnd config
drwxr-xr-x 2 1100 1100 6  7 nov 09.19 config
```

With the above directory permissions, you can start a SFTPGo instance like this:

```shell
docker run --name some-sftpgo \
    --user 1100:1100 \
    -p 8080:8080 \
    -p 2022:2022 \
    --mount type=bind,source="${PWD}/data",target=/srv/sftpgo \
    --mount type=bind,source="${PWD}/config",target=/var/lib/sftpgo \
    -d "drakkan/sftpgo:tag"
```

Alternately build your own image using the official one as a base, here is a sample Dockerfile:

```shell
FROM drakkan/sftpgo:tag
USER root
RUN chown -R 1100:1100 /etc/sftpgo && chown 1100:1100 /var/lib/sftpgo /srv/sftpgo
USER 1100:1100
```

**Note:** the above Dockerfile will not work if you use the [distroless](../Dockerfile.distroless) image as base since the `chown` command is not available there.

## Image Variants

The `sftpgo` images comes in many flavors, each designed for a specific use case. The `edge`, `edge-slim`, `edge-alpine`, `edge-alpine-slim` and `edge-distroless-slim` tags are updated after each new commit.

### `sftpgo:<version>`

This is the defacto image, it is based on [Debian](https://www.debian.org/), available in [the `debian` official image](https://hub.docker.com/_/debian). If you are unsure about what your needs are, you probably want to use this one.

### `sftpgo:<version>-alpine`

This image is based on the popular [Alpine Linux project](https://alpinelinux.org/), available in [the `alpine` official image](https://hub.docker.com/_/alpine). Alpine Linux is much smaller than most distribution base images (~5MB), and thus leads to much slimmer images in general.

This variant is highly recommended when final image size being as small as possible is desired. The main caveat to note is that it does use [musl libc](https://musl.libc.org/) instead of [glibc and friends](https://www.etalabs.net/compare_libcs.html), so certain software might run into issues depending on the depth of their libc requirements. However, most software doesn't have an issue with this, so this variant is usually a very safe choice. See [this Hacker News comment thread](https://news.ycombinator.com/item?id=10782897) for more discussion of the issues that might arise and some pro/con comparisons of using Alpine-based images.

### `sftpgo:<version>-distroless`

This image is based on the popular [Distroless project](https://github.com/GoogleContainerTools/distroless). We use the latest Debian based distroless image as base.

Distroless variant contains only a statically linked sftpgo binary and its minimal runtime dependencies and so it doesn't allow shell access (no shell is installed).
SQLite support is disabled since it requires CGO and so a C runtime which is not installed.
The default data provider is `bolt`, all the supported data providers except `sqlite` work.
We only provide the slim variant and so the optional `git` dependency is not available.

### `sftpgo:<suite>-slim`

These tags provide a slimmer image that does not include the optional `git` dependency.

## Helm Chart

An helm chart is [available](https://artifacthub.io/packages/helm/sagikazarmark/sftpgo). You can find the source code [here](https://github.com/sagikazarmark/helm-charts/tree/master/charts/sftpgo).
