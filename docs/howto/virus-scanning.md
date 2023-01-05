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
