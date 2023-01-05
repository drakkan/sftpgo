# Virus Scanning

It is always good to detect viruses and with the
[Event Manager](https://github.com/drakkan/sftpgo/blob/main/docs/howto/eventmanager.md) in SFTPGo
it is easy to scan all uploaded files on the fly immediately once they are uploaded.

## Prerequisite

Before following this example you probably need to be able to run both ClamAV and SFTPGo in a container.
Please look at the respective documentation for both
[ClamAV](https://github.com/Cisco-Talos/clamav-documentation/blob/main/src/manual/Installing/Docker.md)
and [SFTPGo](https://github.com/drakkan/sftpgo/blob/main/docker/README.md) 

### Building your own SFTPGo image

The default SFTPGo docker image does not contain clamdscan, so you will have to build your own image.
In this example I base my image on the official SFTPGo docker image, and I will not get into many
details of image building.

### Dockerfile

First you need a Dockerfile, and here is the bare essential version of my Dockerfile.

```
FROM docker.io/drakkan/sftpgo:plugins
USER root
RUN apt-get update && apt-get install -y apt-utils && apt-get upgrade -y
RUN apt-get install -y clamdscan file
COPY clamd.conf /etc/clamav/
USER sftpgo
```
### podman build

I use podman because I want the pod functionality and also to be able to run rootless containers. You can
probably use docker to build the image as well or buildah, but that is beyond the scope of this document.

`podman build --tag plugins_clamdscan --file Dockerfile`

You should now have a SFTPGo image with clamdscan and you should be able to continue with pod and container creation.
If not, please consult other documentation for how to build an image.


## podman pod example

This example is based on my own setup which is podman pod based with podman containers both for SFTPGo and ClamAV,
but a similar combination of SFTPGo and ClamAV should be possible in docker and Kubernetes, as well as with either
both SFTPGo and ClamAV as daemons or a combination of containers and daemons.

### pod creation

First create a pod with all the exposed ports needed to access and use your SFTPGo. Notice that in this example
I do not expose any ClamAV ports, and that is because I let SFTPGo freely access ClamAV internally in the pod to keep
ClamAV hidden and (more) protected.

```shell
podman pod create \
	--name pod-sftpgo-clamav \
	--infra-name sftpgo-clamav-infra \
	-p 50000-50199:50000-50199 \
	-p 8443:8443 \
	-p 2022:2022 \
	-p 2121:2121 
```

### How ClamAV container accesses files in SFTPGo container

Because ClamAV and SFTPGo does not run in the same container the default setup would not allow ClamAV to read the
files in SFTPGo. The 2 obvious methods to give ClamAV access to the files is either a) to use `--stream` when calling
clamdscan or b) simply mount the filesystem in both SFTPGo and ClamAV containers which is what I do in this example.
Notice that I mount the filesystems on the same location in both ClamAV and SFTPGo.

### ClamAV container creation

```shell
IMAGE="docker.io/clamav/clamav:stable"
NAME="dmz-clamav"

podman create --name ${NAME} \
	--pod pod-sftpgo-clamav \
	--restart=on-failure \
	-v "srv_sftpgo:/srv/sftpgo/" \
	"${IMAGE}"
```


