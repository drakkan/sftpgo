# Virus Scanning

It is always good to detect viruses and with the
[Event Manager](https://github.com/drakkan/sftpgo/blob/main/docs/howto/eventmanager.md) in SFTPGo
it is easy to scan all uploaded files on the fly immediately once they are uploaded.

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
	-v "srv_sftpgo_bin:/srv/sftpgo/bin" \
	"${IMAGE}"
```

### SFTPGo image creation

The default SFTPGo docker image does not contain clamdscan, so you will have to build your own image.
In this example I base my image on the official SFTPGo docker image, and I will not get into many
details of image building or how to actually run SFTPGO in a container.

