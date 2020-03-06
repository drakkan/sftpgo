
  
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
RAM| 64GB 2400MHz ECC |
Disk| 3* Intel P4510 4TB RAID0 |
Ethernet| Mellanox ConnectX-3 40GbE|

**Client** ||
--- | --- |
OS| Ubuntu 19.10 x64 |
CPU| Threadripper 1920X |
RAM| 64GB 2400MHz ECC |
Disk| Samsung 960EVO 1TB |
Ethernet| Mellanox ConnectX-3 40GbE|

### Test configuration
`Baseline`: Released version 0.9.6.

`Optimized`: Various [optimizations](#Optimizations-applied) applied on top of 0.9.5.

`Balanced`:  Two optimized instance load balanced by HAProxy 2.1.3.

`OpenSSH`: OpenSSH_7.9p1 Debian-10+deb10u2, OpenSSL 1.1.1d  10 Sep 2019

Server's CPU is in Eco mode, you can expect better result in certain cases with a stronger CPU, especially multi-stream HAProxy balanced load.

#### Cipher aes128-ctr
##### SFTP
Download:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|149|306|370|378|
2|265|576|675|720|
3|341|807|880|1002|
4|402|1024|1150|1222|
8|518|1749|1400|1815|

Upload:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|165|292|340|355|
2|262|453|490|633|
3|327|566|560|726|
4|376|647|650|788|
8|478|735|700|806|

##### SCP
Download:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|215|509|579|470|
2|433|928|1097|828|
3|613|1327|1346|1174|
4|824|1670|1576|1424|
8|1281|2656|2049|1870|

Upload:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|189|354|393|428|
2|312|510|570|668|
3|401|621|664|803|
4|481|705|723|840|
8|652|767|799|884|

#### Cipher aes128gcm@openssh.com
##### SFTP
Download:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|322|388|561|401|
2|518|734|976|810|
3|638|1067|1214|1072|
4|723|1283|1415|1288|
8|844|2072|1742|1842|

Upload:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|318|353|415|381|
2|473|542|573|670|
3|569|672|657|757|
4|621|730|721|758|
8|694|825|763|815|

##### SCP
Download:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|669|734|818|447|
2|1218|1320|1367|883|
3|1752|1738|1755|1217|
4|2202|2238|2038|1475|
8|3151|3184|2391|1941|

Upload:

Stream|Baseline MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|
1|446|446|494|448|
2|616|623|646|650|
3|746|749|728|741|
4|833|832|788|858|
8|897|903|823|887|

### Optimizations applied
- AES-CTR optimization of golang compiler, the patch hasn't been merged yet, you can apply it yourself. [patch](https://go-review.googlesource.com/c/go/+/51670)
- Use minio/sha256-simd to accelerate MAC computation.
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
- A new allocator which greatly improve parallel loads.
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
