# Performance

SFTPGo can easily saturate a Gigabit connection on low end hardware with no special configuration, this is generally enough for most use cases.

For Multi-Gig connections, some performance improvements and comparisons with OpenSSH have been discussed [here](https://github.com/drakkan/sftpgo/issues/69), most of them have been included in the main branch. To summarize:

- In current state with all performance improvements applied, SFTP performance is very close to OpenSSH however CPU usage is higher. SCP performance match OpenSSH.
- The main bottlenecks are the encryption and the messages authentication, so if you can use a fast cipher with implicit messages authentication, such as `aes128-gcm@openssh.com`, you will get a big performance boost.
- SCP protocol is much simpler than SFTP and so, the multi-platform, SFTPGo's SCP implementation performs better than SFTP.
- Load balancing with HAProxy can greatly improve the performance if CPU not become the bottleneck.

## Benchmark

### Hardware specification

**Server** ||
--- | --- |
OS| Debian 10.2 x64 |
CPU| Ryzen5 3600 |
RAM| 64GB 2400MHz ECC |
Disk| Ramdisk |
Ethernet| Mellanox ConnectX-3 40GbE|

**Client** ||
--- | --- |
OS| Ubuntu 19.10 x64 |
CPU| Threadripper 1920X |
RAM| 64GB 2400MHz ECC |
Disk| Ramdisk |
Ethernet| Mellanox ConnectX-3 40GbE|

### Test configurations

- `Baseline`: SFTPGo version 0.9.6.
- `Devel`: SFTPGo commit b0ed1905918b9dcc22f9a20e89e354313f491734, compiled with Golang 1.14.2. This is basically the same as v1.0.0 as far as performance is concerned.
- `Optimized`: Various [optimizations](#Optimizations-applied) applied on top of `Devel`.
- `Balanced`: Two optimized instances, running on localhost, load balanced by HAProxy 2.1.3.
- `OpenSSH`: OpenSSH_7.9p1 Debian-10+deb10u2, OpenSSL 1.1.1d  10 Sep 2019

Server's CPU is in Eco mode, you can expect better results in certain cases with a stronger CPU, especially multi-stream HAProxy balanced load.

#### Cipher aes128-ctr

The Message Authentication Code (MAC) used is `hmac-sha2-256`.

##### SFTP

Download:

Stream|Baseline MB/s|Devel MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|---|
1|150|243|319|412|452|
2|267|452|600|740|735|
3|351|637|802|991|1045|
4|414|811|1002|1192|1265|
8|536|1451|1742|1552|1798|

Upload:

Stream|Baseline MB/s|Devel MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|---|
1|172|273|343|407|426|
2|284|469|595|673|738|
3|368|644|820|881|1090|
4|446|851|1041|1026|1244|
8|605|1210|1368|1273|1820|

##### SCP

Download:

Stream|Baseline MB/s|Devel MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|---|
1|220|369|525|611|558|
2|437|659|941|1048|856|
3|635|1000|1365|1363|1201|
4|787|1272|1664|1610|1415|
8|1297|2129|2690|2100|1959|

Upload:

Stream|Baseline MB/s|Devel MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|---|
1|208|312|400|458|508|
2|360|516|647|745|926|
3|476|678|861|935|1254|
4|576|836|1080|1099|1569|
8|857|1161|1416|1433|2271|

#### Cipher aes128-gcm@openssh.com

With this cipher the messages authentication is implicit, no SHA256 computation is needed.

##### SFTP

Download:

Stream|Baseline MB/s|Devel MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|---|
1|332|423|<--|583|443|
2|533|755|<--|970|809|
3|666|1045|<--|1249|1098|
4|762|1276|<--|1461|1351|
8|886|2064|<--|1825|1933|

Upload:

Stream|Baseline MB/s|Devel MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|---|
1|348|410|<--|527|469|
2|596|729|<--|842|930|
3|778|974|<--|1088|1341|
4|886|1192|<--|1232|1494|
8|1042|1578|<--|1433|1893|

##### SCP

Download:

Stream|Baseline MB/s|Devel MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|---|
1|776|793|<--|832|578|
2|1343|1415|<--|1435|938|
3|1815|1878|<--|1877|1279|
4|2192|2205|<--|2056|1567|
8|3237|3287|<--|2493|2036|

Upload:

Stream|Baseline MB/s|Devel MB/s|Optimized MB/s|Balanced MB/s|OpenSSH MB/s|
---|---|---|---|---|---|
1|528|545|<--|608|584|
2|872|849|<--|975|1019|
3|1121|1138|<--|1217|1412|
4|1367|1387|<--|1368|1755|
8|1733|1744|<--|1664|2510|

### Optimizations applied

- AES-CTR optimization of Go compiler for x86_64, there is a [patch](https://go-review.googlesource.com/c/go/+/51670) that hasn't been merged yet, you can apply it yourself.

### HAProxy configuration

Here is the relevant HAProxy configuration used for the `Balanced` test configuration:

```console
frontend sftp
    bind   :2222
    mode   tcp
    timeout  client  600s
    default_backend sftpgo

backend sftpgo
    mode    tcp
    balance roundrobin
    timeout connect 10s
    timeout server  600s
    timeout queue   30s
    option  tcp-check
    tcp-check expect string SSH-2.0-

    server sftpgo1 127.0.0.1:2022 check send-proxy-v2 weight 10 inter 10s rise 2 fall 3
    server sftpgo2 127.0.0.1:2024 check send-proxy-v2 weight 10 inter 10s rise 2 fall 3
```
