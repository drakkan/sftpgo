# Virus Scanning

It is always good to detect viruses and with the
[Event Manager](https://github.com/drakkan/sftpgo/blob/main/docs/howto/eventmanager.md) in SFTPGo
it is easy to scan all uploaded files on the fly immediately once they are uploaded.

## Prerequisite

Before following this example you probably need to be able to run both ClamAV and SFTPGo in a container.
Please look at the respective documentation for both
[ClamAV](https://github.com/Cisco-Talos/clamav-documentation/blob/main/src/manual/Installing/Docker.md)
and [SFTPGo](https://github.com/drakkan/sftpgo/blob/main/docker/README.md).
It is also a good idea to look at the
[Event Manager](https://github.com/drakkan/sftpgo/blob/main/docs/howto/eventmanager.md)
documentation for SFTPGo, but it is not needed for basic manually started virus scanning.

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
Notice that I mount the filesystems on the same location in both ClamAV and SFTPGo because then I can from inside the
SFTPGo container just call clamdscan with the path to the file, and then clamd inside the ClamAV container can use that to access the same file directly inside it's own container.

### ClamAV container creation

The default ClamAV container does not enable neither the `TCPSocket 3310` or the `TCPAddr localhost` by default,
so I mount a new clamd.conf inside the ClamAV container. This is the same clamd.conf that I copied into my SFTPGo
image above. The localhost that I bind clamd to is the localhost inside the ClamAV container, inside ANY ClamAV
container I create. For more details of clamd.conf please consult your local `man clamd.conf` or simular documentation.

```shell
IMAGE="docker.io/clamav/clamav:stable"
podman create --name dmz-clamav \
	--pod pod-sftpgo-clamav \
	-v "srv_sftpgo:/srv/sftpgo/" \
	-v "$(pwd)/clamd.conf:/etc/clamav/clamd.conf" \
	"${IMAGE}"
```

### SFTPGo container creation

We could mount the same clamd.conf inside the SFTPGo container as we do inside the ClamAV container, but I chose to include it in my SFTPGo image creation above because it does not contain any secret or unique information and I like to keep the container creation as simple as possible.

```
IMAGE="drakkan/sftpgo:plugins_clamdscan"
podman create --name some-sftpgo \
	--pod pod-sftpgo-clamav \
	-v "srv_sftpgo:/srv/sftpgo/" \
	"${IMAGE}" \
```

### Starting the pod

You should now have a pod which contains 3 containers: infra, ClamAV and SFTPGo. The details of the infra container is irrelevant to this document, but you can read a little more about it
[here](https://developers.redhat.com/blog/2019/01/15/podman-managing-containers-pods).
Starting the pod with this command `podman pod start pod-sftpgo-clamav` will start all 3 containers in the pod and SFTPGo should be accessible just like if it was running as a standalone container.


## Using clamdscan inside SFTPGo

To use clamdscan inside your SFTPGo container in the pod you just created you simply just run the clamdscan command just like in most other usecases `clamdscan /path/to/file` because inside the pod all containers share localhost so from inside the SFTPGo container you can easily access localhost inside the ClamAV container, but anyone outside the pod can not access the same localhost, and thus not ClamAV.

### Getting SFTPGo to clamdscan files when uploaded

It is beyond the scope of this document to get deep into details about how to create an event in SFTPGo that triggers on Uploads and executes a shell script. For information about that, please consult the
[Event Manager](https://github.com/drakkan/sftpgo/blob/main/docs/howto/eventmanager.md)
documentation.

## Lifecycle management

From time to time ClamAV needs to update it's virus definition. The default ClamAV container does that once pr. day, and it does not seem to have any downtime when clamd can not be accessed from inside the SFTPGo container.

### 30 second startup time

However if you want to upgrade the whole ClamAV container then you might experience a ~30 seconds delay after starting your ClamAV container until you can actually use clamdscan from within your SFTPGo container.

Because my planned SFTPGo usecase can and do receive multiple files from multiple users almost on a pr. minute basis 365x7x24 then that 30 second startup time is not acceptable. What I do is then just to run multiple ClamAV containers inside the same pod, all of them on their own individual TCPSocket.

```
root@pod-sftpgo-clamav:~# grep TCPSocket /etc/clamav/*.clamd.conf
/etc/clamav/3310.clamd.conf:TCPSocket 3310
/etc/clamav/3311.clamd.conf:TCPSocket 3311
```

In the above example I run 2, but you can easily add more clamd.conf configuration files inside your SFTPGo container and just cycle through them until you find a clamd that responds. Note that inside the ClamAV container there is only 1 clamd.conf file, it just has to contain a different `TCPSocket` line than any of the other ClamAV containers and they all have to be a part of the same pod as SFTPGo. I name my ClamAV containers with a basename and then adds the port number to that basename so I can easily see the difference.
