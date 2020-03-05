
# Performance

SFTPGo can easily saturate a Gigabit connection on low end hardware with no special configuration, and this is generally enough for most use cases.

For Multi-Gig connections, some performance improvements and comparisons with OpenSSH have been discussed here [issue](https://github.com/drakkan/sftpgo/issues/69),  some of them need upstream updates so there are not included in the released version (0.9.5) yet. To summarize:
- In current state with all performance improvements applied, SFTP performance is very close to OpenSSH however CPU usage is higher. SCP performance match OpenSSH.
- The main bottlenecks are the encryption and the messages authentication, so if you can use a fast cipher with implicit message authentication, such as `aes128-gcm@openssh.com`, you will get a big performance boost.
- SFTPGo's SCP implementation is more efficient than SFTP, in *nix environment it performs better than SFTP. 
- Load balancing with HAProxy can greatly improve the performance if CPU not become the bottleneck.

## Benchmark
### Hardware specification
**Server** ||
--- | --- |
OS| Debian 10.2 x64 |
CPU| Ryzen5 3600 |
RAM| 64GB ECC |
Disk| 3* Intel P4510 4TB RAID0 |
Ethernet| Mellanox ConnectX-3 40GbE|

**Client** ||
--- | --- |
OS| Ubuntu 19.10 x64 |
CPU| Threadripper 1920X |
RAM| 64GB ECC |
Disk| Samsung 960EVO 1TB |
Ethernet| Mellanox ConnectX-3 40GbE|

### Test configuration
`Baseline`: Released version 0.9.5.

`Optimized`: Various [optimizations](#Optimizations-applied) applied on top of 0.9.5.

`Balanced`:  Two optimized instance load balanced by HAProxy 2.1.3.

`OpenSSH`: OpenSSH_7.9p1 Debian-10+deb10u2, OpenSSL 1.1.1d  10 Sep 2019

#### Cipher aes128-ctr
##### SFTP
Download:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|125|280|370|380|
2|210|520|675|600|
3|260|760|880|700|
4|330|1100|1150|810|
8|387|1850|1400|950|

Upload:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1||280|340||
2||440|490||
3||520|560||
4||570|650||
8||690|700||

##### SCP
Download:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|380|||384|
2|750|||720|
3|1100|||1050|
4|1350|||1250|
8|2100|||1850|

Upload:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1||340|||
2||520|||
3||630|||
4||700|||
8||830|||

#### Cipher aes128gcm@openssh.com
##### SFTP
Download:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|260||500|340|
2|420||900|640|
3|500||1100|800|
4|580||1500|1000|
8|700||1600|1450|

Upload:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|||420||
2|||550||
3|||600||
4|||700||
8|||750||

##### SCP
Download:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|500|||360|
2|950|||680|
3|1350|||980|
4|1650|||1100|
8|2400|||1550|

Upload:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|||||
2|||||
3|||||
4|||||
8|||||

### Optimizations applied
- AES-CTR optimization of golang compiler hasn't been merged yet, you can apply the patch yourself. [patch](https://go-review.googlesource.com/c/go/+/51670)
- Use minio/sha256-simd to accelerate MAC computation, which could improve the performance by 50% on newer CPU architectures.
```
diff --git a/go.mod b/go.mod
index f1b2caa..a3e2ba5 100644
--- a/go.mod
+++ b/go.mod
@@ -43,3 +43,5 @@ require (
 )
 
 replace github.com/eikenb/pipeat v0.0.0-20190316224601-fb1f3a9aa29f => github.com/drakkan/pipeat v0.0.0-20200123131427-11c048cfc0ec
+
+golang.org/x/crypto => github.com/drakkan/crypto v0.0.0-20200211081002-cc78d71334be
```
- A new allocator which greatly improve parallel loads is being tested here.
```
diff --git a/go.mod b/go.mod
index f1b2caa..4a3be8a 100644
--- a/go.mod
+++ b/go.mod
@@ -43,3 +43,5 @@ require (
 )
 
 replace github.com/eikenb/pipeat v0.0.0-20190316224601-fb1f3a9aa29f => github.com/drakkan/pipeat v0.0.0-20200123131427-11c048cfc0ec
+
+replace github.com/pkg/sftp => github.com/drakkan/sftp v0.0.0-20200227085621-6b4abaad1b9a
```







