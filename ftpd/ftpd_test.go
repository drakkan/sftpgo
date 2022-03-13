package ftpd_test

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/jlaffaye/ftp"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"github.com/sftpgo/sdk"
	sdkkms "github.com/sftpgo/sdk/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/ftpd"
	"github.com/drakkan/sftpgo/v2/httpdtest"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/sftpd"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	logSender       = "ftpdTesting"
	ftpServerAddr   = "127.0.0.1:2121"
	sftpServerAddr  = "127.0.0.1:2122"
	ftpSrvAddrTLS   = "127.0.0.1:2124" // ftp server with implicit tls
	defaultUsername = "test_user_ftp"
	defaultPassword = "test_password"
	configDir       = ".."
	osWindows       = "windows"
	ftpsCert        = `-----BEGIN CERTIFICATE-----
MIICHTCCAaKgAwIBAgIUHnqw7QnB1Bj9oUsNpdb+ZkFPOxMwCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDAyMDQwOTUzMDRaFw0zMDAyMDEw
OTUzMDRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAARCjRMqJ85rzMC998X5z761nJ+xL3bkmGVqWvrJ51t5OxV0v25NsOgR82CA
NXUgvhVYs7vNFN+jxtb2aj6Xg+/2G/BNxkaFspIVCzgWkxiz7XE4lgUwX44FCXZM
3+JeUbKjUzBRMB0GA1UdDgQWBBRhLw+/o3+Z02MI/d4tmaMui9W16jAfBgNVHSME
GDAWgBRhLw+/o3+Z02MI/d4tmaMui9W16jAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
SM49BAMCA2kAMGYCMQDqLt2lm8mE+tGgtjDmtFgdOcI72HSbRQ74D5rYTzgST1rY
/8wTi5xl8TiFUyLMUsICMQC5ViVxdXbhuG7gX6yEqSkMKZICHpO8hqFwOD/uaFVI
dV4vKmHUzwK/eIx+8Ay3neE=
-----END CERTIFICATE-----`
	ftpsKey = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCfMNsN6miEE3rVyUPwElfiJSWaR5huPCzUenZOfJT04GAcQdWvEju3
UM2lmBLIXpGgBwYFK4EEACKhZANiAARCjRMqJ85rzMC998X5z761nJ+xL3bkmGVq
WvrJ51t5OxV0v25NsOgR82CANXUgvhVYs7vNFN+jxtb2aj6Xg+/2G/BNxkaFspIV
CzgWkxiz7XE4lgUwX44FCXZM3+JeUbI=
-----END EC PRIVATE KEY-----`
	caCRT = `-----BEGIN CERTIFICATE-----
MIIE5jCCAs6gAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhDZXJ0
QXV0aDAeFw0yMTAxMDIyMTIwNTVaFw0yMjA3MDIyMTMwNTJaMBMxETAPBgNVBAMT
CENlcnRBdXRoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4Tiho5xW
AC15JRkMwfp3/TJwI2As7MY5dele5cmdr5bHAE+sRKqC+Ti88OJWCV5saoyax/1S
CjxJlQMZMl169P1QYJskKjdG2sdv6RLWLMgwSNRRjxp/Bw9dHdiEb9MjLgu28Jro
9peQkHcRHeMf5hM9WvlIJGrdzbC4hUehmqggcqgARainBkYjf0SwuWxHeu4nMqkp
Ak5tcSTLCjHfEFHZ9Te0TIPG5YkWocQKyeLgu4lvuU+DD2W2lym+YVUtRMGs1Env
k7p+N0DcGU26qfzZ2sF5ZXkqm7dBsGQB9pIxwc2Q8T1dCIyP9OQCKVILdc5aVFf1
cryQFHYzYNNZXFlIBims5VV5Mgfp8ESHQSue+v6n6ykecLEyKt1F1Y/MWY/nWUSI
8zdq83jdBAZVjo9MSthxVn57/06s/hQca65IpcTZV2gX0a+eRlAVqaRbAhL3LaZe
bYsW3WHKoUOftwemuep3nL51TzlXZVL7Oz/ClGaEOsnGG9KFO6jh+W768qC0zLQI
CdE7v2Zex98sZteHCg9fGJHIaYoF0aJG5P3WI5oZf2fy7UIYN9ADLFZiorCXAZEh
CSU6mDoRViZ4RGR9GZxbDZ9KYn7O8M/KCR72bkQg73TlMsk1zSXEw0MKLUjtsw6c
rZ0Jt8t3sRatHO3JrYHALMt9vZfyNCZp0IsCAwEAAaNFMEMwDgYDVR0PAQH/BAQD
AgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO1yCNAGr/zQTJIi8lw3
w5OiuBvMMA0GCSqGSIb3DQEBCwUAA4ICAQA6gCNuM7r8mnx674dm31GxBjQy5ZwB
7CxDzYEvL/oiZ3Tv3HlPfN2LAAsJUfGnghh9DOytenL2CTZWjl/emP5eijzmlP+9
zva5I6CIMCf/eDDVsRdO244t0o4uG7+At0IgSDM3bpVaVb4RHZNjEziYChsEYY8d
HK6iwuRSvFniV6yhR/Vj1Ymi9yZ5xclqseLXiQnUB0PkfIk23+7s42cXB16653fH
O/FsPyKBLiKJArizLYQc12aP3QOrYoYD9+fAzIIzew7A5C0aanZCGzkuFpO6TRlD
Tb7ry9Gf0DfPpCgxraH8tOcmnqp/ka3hjqo/SRnnTk0IFrmmLdarJvjD46rKwBo4
MjyAIR1mQ5j8GTlSFBmSgETOQ/EYvO3FPLmra1Fh7L+DvaVzTpqI9fG3TuyyY+Ri
Fby4ycTOGSZOe5Fh8lqkX5Y47mCUJ3zHzOA1vUJy2eTlMRGpu47Eb1++Vm6EzPUP
2EF5aD+zwcssh+atZvQbwxpgVqVcyLt91RSkKkmZQslh0rnlTb68yxvUnD3zw7So
o6TAf9UvwVMEvdLT9NnFd6hwi2jcNte/h538GJwXeBb8EkfpqLKpTKyicnOdkamZ
7E9zY8SHNRYMwB9coQ/W8NvufbCgkvOoLyMXk5edbXofXl3PhNGOlraWbghBnzf5
r3rwjFsQOoZotA==
-----END CERTIFICATE-----`
	caCRL = `-----BEGIN X509 CRL-----
MIICpzCBkAIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhDZXJ0QXV0aBcN
MjEwMTAyMjEzNDA1WhcNMjMwMTAyMjEzNDA1WjAkMCICEQC+l04DbHWMyC3fG09k
VXf+Fw0yMTAxMDIyMTM0MDVaoCMwITAfBgNVHSMEGDAWgBTtcgjQBq/80EySIvJc
N8OTorgbzDANBgkqhkiG9w0BAQsFAAOCAgEAEJ7z+uNc8sqtxlOhSdTGDzX/xput
E857kFQkSlMnU2whQ8c+XpYrBLA5vIZJNSSwohTpM4+zVBX/bJpmu3wqqaArRO9/
YcW5mQk9Anvb4WjQW1cHmtNapMTzoC9AiYt/OWPfy+P6JCgCr4Hy6LgQyIRL6bM9
VYTalolOm1qa4Y5cIeT7iHq/91mfaqo8/6MYRjLl8DOTROpmw8OS9bCXkzGKdCat
AbAzwkQUSauyoCQ10rpX+Y64w9ng3g4Dr20aCqPf5osaqplEJ2HTK8ljDTidlslv
9anQj8ax3Su89vI8+hK+YbfVQwrThabgdSjQsn+veyx8GlP8WwHLAQ379KjZjWg+
OlOSwBeU1vTdP0QcB8X5C2gVujAyuQekbaV86xzIBOj7vZdfHZ6ee30TZ2FKiMyg
7/N2OqW0w77ChsjB4MSHJCfuTgIeg62GzuZXLM+Q2Z9LBdtm4Byg+sm/P52adOEg
gVb2Zf4KSvsAmA0PIBlu449/QXUFcMxzLFy7mwTeZj2B4Ln0Hm0szV9f9R8MwMtB
SyLYxVH+mgqaR6Jkk22Q/yYyLPaELfafX5gp/AIXG8n0zxfVaTvK3auSgb1Q6ZLS
5QH9dSIsmZHlPq7GoSXmKpMdjUL8eaky/IMteioyXgsBiATzl5L2dsw6MTX3MDF0
QbDK+MzhmbKfDxs=
-----END X509 CRL-----`
	client1Crt = `-----BEGIN CERTIFICATE-----
MIIEITCCAgmgAwIBAgIRAIppZHoj1hM80D7WzTEKLuAwDQYJKoZIhvcNAQELBQAw
EzERMA8GA1UEAxMIQ2VydEF1dGgwHhcNMjEwMTAyMjEyMzEwWhcNMjIwNzAyMjEz
MDUxWjASMRAwDgYDVQQDEwdjbGllbnQxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAoKbYY9MdF2kF/nhBESIiZTdVYtA8XL9xrIZyDj9EnCiTxHiVbJtH
XVwszqSl5TRrotPmnmAQcX3r8OCk+z+RQZ0QQj257P3kG6q4rNnOcWCS5xEd20jP
yhQ3m+hMGfZsotNTQze1ochuQgLUN6IPyPxZkH22ia3jX4iu1eo/QxeLYHj1UHw4
3Cii9yE+j5kPUC21xmnrGKdUrB55NYLXHx6yTIqYR5znSOVB8oJi18/hwdZmH859
DHhm0Hx1HrS+jbjI3+CMorZJ3WUyNf+CkiVLD3xYutPbxzEpwiqkG/XYzLH0habT
cDcILo18n+o3jvem2KWBrDhyairjIDscwQIDAQABo3EwbzAOBgNVHQ8BAf8EBAMC
A7gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBSJ5GIv
zIrE4ZSQt2+CGblKTDswizAfBgNVHSMEGDAWgBTtcgjQBq/80EySIvJcN8OTorgb
zDANBgkqhkiG9w0BAQsFAAOCAgEALh4f5GhvNYNou0Ab04iQBbLEdOu2RlbK1B5n
K9P/umYenBHMY/z6HT3+6tpcHsDuqE8UVdq3f3Gh4S2Gu9m8PRitT+cJ3gdo9Plm
3rD4ufn/s6rGg3ppydXcedm17492tbccUDWOBZw3IO/ASVq13WPgT0/Kev7cPq0k
sSdSNhVeXqx8Myc2/d+8GYyzbul2Kpfa7h9i24sK49E9ftnSmsIvngONo08eT1T0
3wAOyK2981LIsHaAWcneShKFLDB6LeXIT9oitOYhiykhFlBZ4M1GNlSNfhQ8IIQP
xbqMNXCLkW4/BtLhGEEcg0QVso6Kudl9rzgTfQknrdF7pHp6rS46wYUjoSyIY6dl
oLmnoAVJX36J3QPWelePI9e07X2wrTfiZWewwgw3KNRWjd6/zfPLe7GoqXnK1S2z
PT8qMfCaTwKTtUkzXuTFvQ8bAo2My/mS8FOcpkt2oQWeOsADHAUX7fz5BCoa2DL3
k/7Mh4gVT+JYZEoTwCFuYHgMWFWe98naqHi9lB4yR981p1QgXgxO7qBeipagKY1F
LlH1iwXUqZ3MZnkNA+4e1Fglsw3sa/rC+L98HnznJ/YbTfQbCP6aQ1qcOymrjMud
7MrFwqZjtd/SK4Qx1VpK6jGEAtPgWBTUS3p9ayg6lqjMBjsmySWfvRsDQbq6P5Ct
O/e3EH8=
-----END CERTIFICATE-----`
	client1Key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAoKbYY9MdF2kF/nhBESIiZTdVYtA8XL9xrIZyDj9EnCiTxHiV
bJtHXVwszqSl5TRrotPmnmAQcX3r8OCk+z+RQZ0QQj257P3kG6q4rNnOcWCS5xEd
20jPyhQ3m+hMGfZsotNTQze1ochuQgLUN6IPyPxZkH22ia3jX4iu1eo/QxeLYHj1
UHw43Cii9yE+j5kPUC21xmnrGKdUrB55NYLXHx6yTIqYR5znSOVB8oJi18/hwdZm
H859DHhm0Hx1HrS+jbjI3+CMorZJ3WUyNf+CkiVLD3xYutPbxzEpwiqkG/XYzLH0
habTcDcILo18n+o3jvem2KWBrDhyairjIDscwQIDAQABAoIBAEBSjVFqtbsp0byR
aXvyrtLX1Ng7h++at2jca85Ihq//jyqbHTje8zPuNAKI6eNbmb0YGr5OuEa4pD9N
ssDmMsKSoG/lRwwcm7h4InkSvBWpFShvMgUaohfHAHzsBYxfnh+TfULsi0y7c2n6
t/2OZcOTRkkUDIITnXYiw93ibHHv2Mv2bBDu35kGrcK+c2dN5IL5ZjTjMRpbJTe2
44RBJbdTxHBVSgoGBnugF+s2aEma6Ehsj70oyfoVpM6Aed5kGge0A5zA1JO7WCn9
Ay/DzlULRXHjJIoRWd2NKvx5n3FNppUc9vJh2plRHalRooZ2+MjSf8HmXlvG2Hpb
ScvmWgECgYEA1G+A/2KnxWsr/7uWIJ7ClcGCiNLdk17Pv3DZ3G4qUsU2ITftfIbb
tU0Q/b19na1IY8Pjy9ptP7t74/hF5kky97cf1FA8F+nMj/k4+wO8QDI8OJfzVzh9
PwielA5vbE+xmvis5Hdp8/od1Yrc/rPSy2TKtPFhvsqXjqoUmOAjDP8CgYEAwZjH
9dt1sc2lx/rMxihlWEzQ3JPswKW9/LJAmbRBoSWF9FGNjbX7uhWtXRKJkzb8ZAwa
88azluNo2oftbDD/+jw8b2cDgaJHlLAkSD4O1D1RthW7/LKD15qZ/oFsRb13NV85
ZNKtwslXGbfVNyGKUVFm7fVA8vBAOUey+LKDFj8CgYEAg8WWstOzVdYguMTXXuyb
ruEV42FJaDyLiSirOvxq7GTAKuLSQUg1yMRBIeQEo2X1XU0JZE3dLodRVhuO4EXP
g7Dn4X7Th9HSvgvNuIacowWGLWSz4Qp9RjhGhXhezUSx2nseY6le46PmFavJYYSR
4PBofMyt4PcyA6Cknh+KHmkCgYEAnTriG7ETE0a7v4DXUpB4TpCEiMCy5Xs2o8Z5
ZNva+W+qLVUWq+MDAIyechqeFSvxK6gRM69LJ96lx+XhU58wJiFJzAhT9rK/g+jS
bsHH9WOfu0xHkuHA5hgvvV2Le9B2wqgFyva4HJy82qxMxCu/VG/SMqyfBS9OWbb7
ibQhdq0CgYAl53LUWZsFSZIth1vux2LVOsI8C3X1oiXDGpnrdlQ+K7z57hq5EsRq
GC+INxwXbvKNqp5h0z2MvmKYPDlGVTgw8f8JjM7TkN17ERLcydhdRrMONUryZpo8
1xTob+8blyJgfxZUIAKbMbMbIiU0WAF0rfD/eJJwS4htOW/Hfv4TGA==
-----END RSA PRIVATE KEY-----`
	// client 2 crt is revoked
	client2Crt = `-----BEGIN CERTIFICATE-----
MIIEITCCAgmgAwIBAgIRAL6XTgNsdYzILd8bT2RVd/4wDQYJKoZIhvcNAQELBQAw
EzERMA8GA1UEAxMIQ2VydEF1dGgwHhcNMjEwMTAyMjEyMzIwWhcNMjIwNzAyMjEz
MDUxWjASMRAwDgYDVQQDEwdjbGllbnQyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA6xjW5KQR3/OFQtV5M75WINqQ4AzXSu6DhSz/yumaaQZP/UxY+6hi
jcrFzGo9MMie/Sza8DhkXOFAl2BelUubrOeB2cl+/Gr8OCyRi2Gv6j3zCsuN/4jQ
tNaoez/IbkDvI3l/ZpzBtnuNY2RiemGgHuORXHRVf3qVlsw+npBIRW5rM2HkO/xG
oZjeBErWVu390Lyn+Gvk2TqQDnkutWnxUC60/zPlHhXZ4BwaFAekbSnjsSDB1YFM
s8HwW4oBryoxdj3/+/qLrBHt75IdLw3T7/V1UDJQM3EvSQOr12w4egpldhtsC871
nnBQZeY6qA5feffIwwg/6lJm70o6S6OX6wIDAQABo3EwbzAOBgNVHQ8BAf8EBAMC
A7gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBTB84v5
t9HqhLhMODbn6oYkEQt3KzAfBgNVHSMEGDAWgBTtcgjQBq/80EySIvJcN8OTorgb
zDANBgkqhkiG9w0BAQsFAAOCAgEALGtBCve5k8tToL3oLuXp/oSik6ovIB/zq4I/
4zNMYPU31+ZWz6aahysgx1JL1yqTa3Qm8o2tu52MbnV10dM7CIw7c/cYa+c+OPcG
5LF97kp13X+r2axy+CmwM86b4ILaDGs2Qyai6VB6k7oFUve+av5o7aUrNFpqGCJz
HWdtHZSVA3JMATzy0TfWanwkzreqfdw7qH0yZ9bDURlBKAVWrqnCstva9jRuv+AI
eqxr/4Ro986TFjJdoAP3Vr16CPg7/B6GA/KmsBWJrpeJdPWq4i2gpLKvYZoy89qD
mUZf34RbzcCtV4NvV1DadGnt4us0nvLrvS5rL2+2uWD09kZYq9RbLkvgzF/cY0fz
i7I1bi5XQ+alWe0uAk5ZZL/D+GTRYUX1AWwCqwJxmHrMxcskMyO9pXvLyuSWRDLo
YNBrbX9nLcfJzVCp+X+9sntTHjs4l6Cw+fLepJIgtgqdCHtbhTiv68vSM6cgb4br
6n2xrXRKuioiWFOrTSRr+oalZh8dGJ/xvwY8IbWknZAvml9mf1VvfE7Ma5P777QM
fsbYVTq0Y3R/5hIWsC3HA5z6MIM8L1oRe/YyhP3CTmrCHkVKyDOosGXpGz+JVcyo
cfYkY5A3yFKB2HaCwZSfwFmRhxkrYWGEbHv3Cd9YkZs1J3hNhGFZyVMC9Uh0S85a
6zdDidU=
-----END CERTIFICATE-----`
	client2Key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA6xjW5KQR3/OFQtV5M75WINqQ4AzXSu6DhSz/yumaaQZP/UxY
+6hijcrFzGo9MMie/Sza8DhkXOFAl2BelUubrOeB2cl+/Gr8OCyRi2Gv6j3zCsuN
/4jQtNaoez/IbkDvI3l/ZpzBtnuNY2RiemGgHuORXHRVf3qVlsw+npBIRW5rM2Hk
O/xGoZjeBErWVu390Lyn+Gvk2TqQDnkutWnxUC60/zPlHhXZ4BwaFAekbSnjsSDB
1YFMs8HwW4oBryoxdj3/+/qLrBHt75IdLw3T7/V1UDJQM3EvSQOr12w4egpldhts
C871nnBQZeY6qA5feffIwwg/6lJm70o6S6OX6wIDAQABAoIBAFatstVb1KdQXsq0
cFpui8zTKOUiduJOrDkWzTygAmlEhYtrccdfXu7OWz0x0lvBLDVGK3a0I/TGrAzj
4BuFY+FM/egxTVt9in6fmA3et4BS1OAfCryzUdfK6RV//8L+t+zJZ/qKQzWnugpy
QYjDo8ifuMFwtvEoXizaIyBNLAhEp9hnrv+Tyi2O2gahPvCHsD48zkyZRCHYRstD
NH5cIrwz9/RJgPO1KI+QsJE7Nh7stR0sbr+5TPU4fnsL2mNhMUF2TJrwIPrc1yp+
YIUjdnh3SO88j4TQT3CIrWi8i4pOy6N0dcVn3gpCRGaqAKyS2ZYUj+yVtLO4KwxZ
SZ1lNvECgYEA78BrF7f4ETfWSLcBQ3qxfLs7ibB6IYo2x25685FhZjD+zLXM1AKb
FJHEXUm3mUYrFJK6AFEyOQnyGKBOLs3S6oTAswMPbTkkZeD1Y9O6uv0AHASLZnK6
pC6ub0eSRF5LUyTQ55Jj8D7QsjXJueO8v+G5ihWhNSN9tB2UA+8NBmkCgYEA+weq
cvoeMIEMBQHnNNLy35bwfqrceGyPIRBcUIvzQfY1vk7KW6DYOUzC7u+WUzy/hA52
DjXVVhua2eMQ9qqtOav7djcMc2W9RbLowxvno7K5qiCss013MeWk64TCWy+WMp5A
AVAtOliC3hMkIKqvR2poqn+IBTh1449agUJQqTMCgYEAu06IHGq1GraV6g9XpGF5
wqoAlMzUTdnOfDabRilBf/YtSr+J++ThRcuwLvXFw7CnPZZ4TIEjDJ7xjj3HdxeE
fYYjineMmNd40UNUU556F1ZLvJfsVKizmkuCKhwvcMx+asGrmA+tlmds4p3VMS50
KzDtpKzLWlmU/p/RINWlRmkCgYBy0pHTn7aZZx2xWKqCDg+L2EXPGqZX6wgZDpu7
OBifzlfM4ctL2CmvI/5yPmLbVgkgBWFYpKUdiujsyyEiQvWTUKhn7UwjqKDHtcsk
G6p7xS+JswJrzX4885bZJ9Oi1AR2yM3sC9l0O7I4lDbNPmWIXBLeEhGMmcPKv/Kc
91Ff4wKBgQCF3ur+Vt0PSU0ucrPVHjCe7tqazm0LJaWbPXL1Aw0pzdM2EcNcW/MA
w0kqpr7MgJ94qhXCBcVcfPuFN9fBOadM3UBj1B45Cz3pptoK+ScI8XKno6jvVK/p
xr5cb9VBRBtB9aOKVfuRhpatAfS2Pzm2Htae9lFn7slGPUmu2hkjDw==
-----END RSA PRIVATE KEY-----`
	testFileName       = "test_file_ftp.dat"
	testDLFileName     = "test_download_ftp.dat"
	tlsClient1Username = "client1"
	tlsClient2Username = "client2"
)

var (
	allPerms        = []string{dataprovider.PermAny}
	homeBasePath    string
	hookCmdPath     string
	extAuthPath     string
	preLoginPath    string
	postConnectPath string
	preDownloadPath string
	preUploadPath   string
	logFilePath     string
	caCrtPath       string
	caCRLPath       string
)

func TestMain(m *testing.M) {
	logFilePath = filepath.Join(configDir, "sftpgo_ftpd_test.log")
	bannerFileName := "banner_file"
	bannerFile := filepath.Join(configDir, bannerFileName)
	logger.InitLogger(logFilePath, 5, 1, 28, false, false, zerolog.DebugLevel)
	err := os.WriteFile(bannerFile, []byte("SFTPGo test ready\nsimple banner line\n"), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error creating banner file: %v", err)
	}
	// we run the test cases with UploadMode atomic and resume support. The non atomic code path
	// simply does not execute some code so if it works in atomic mode will
	// work in non atomic mode too
	os.Setenv("SFTPGO_COMMON__UPLOAD_MODE", "2")
	os.Setenv("SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN", "1")
	os.Setenv("SFTPGO_DEFAULT_ADMIN_USERNAME", "admin")
	os.Setenv("SFTPGO_DEFAULT_ADMIN_PASSWORD", "password")
	err = config.LoadConfig(configDir, "")
	if err != nil {
		logger.ErrorToConsole("error loading configuration: %v", err)
		os.Exit(1)
	}
	providerConf := config.GetProviderConf()
	logger.InfoToConsole("Starting FTPD tests, provider: %v", providerConf.Driver)

	commonConf := config.GetCommonConfig()
	homeBasePath = os.TempDir()
	if runtime.GOOS != osWindows {
		commonConf.Actions.ExecuteOn = []string{"download", "upload", "rename", "delete"}
		commonConf.Actions.Hook = hookCmdPath
		hookCmdPath, err = exec.LookPath("true")
		if err != nil {
			logger.Warn(logSender, "", "unable to get hook command: %v", err)
			logger.WarnToConsole("unable to get hook command: %v", err)
		}
	}

	certPath := filepath.Join(os.TempDir(), "test_ftpd.crt")
	keyPath := filepath.Join(os.TempDir(), "test_ftpd.key")
	caCrtPath = filepath.Join(os.TempDir(), "test_ftpd_ca.crt")
	caCRLPath = filepath.Join(os.TempDir(), "test_ftpd_crl.crt")
	err = writeCerts(certPath, keyPath, caCrtPath, caCRLPath)
	if err != nil {
		os.Exit(1)
	}

	err = common.Initialize(commonConf, 0)
	if err != nil {
		logger.WarnToConsole("error initializing common: %v", err)
		os.Exit(1)
	}
	err = dataprovider.Initialize(providerConf, configDir, true)
	if err != nil {
		logger.ErrorToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}

	httpConfig := config.GetHTTPConfig()
	httpConfig.Initialize(configDir) //nolint:errcheck

	kmsConfig := config.GetKMSConfig()
	err = kmsConfig.Initialize()
	if err != nil {
		logger.ErrorToConsole("error initializing kms: %v", err)
		os.Exit(1)
	}
	mfaConfig := config.GetMFAConfig()
	err = mfaConfig.Initialize()
	if err != nil {
		logger.ErrorToConsole("error initializing MFA: %v", err)
		os.Exit(1)
	}

	httpdConf := config.GetHTTPDConfig()
	httpdConf.Bindings[0].Port = 8079
	httpdtest.SetBaseURL("http://127.0.0.1:8079")

	ftpdConf := config.GetFTPDConfig()
	ftpdConf.Bindings = []ftpd.Binding{
		{
			Port:           2121,
			ClientAuthType: 2,
		},
	}
	ftpdConf.PassivePortRange.Start = 0
	ftpdConf.PassivePortRange.End = 0
	ftpdConf.BannerFile = bannerFileName
	ftpdConf.CertificateFile = certPath
	ftpdConf.CertificateKeyFile = keyPath
	ftpdConf.CACertificates = []string{caCrtPath}
	ftpdConf.CARevocationLists = []string{caCRLPath}
	ftpdConf.EnableSite = true

	// required to test sftpfs
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Bindings = []sftpd.Binding{
		{
			Port: 2122,
		},
	}
	hostKeyPath := filepath.Join(os.TempDir(), "id_ed25519")
	sftpdConf.HostKeys = []string{hostKeyPath}

	extAuthPath = filepath.Join(homeBasePath, "extauth.sh")
	preLoginPath = filepath.Join(homeBasePath, "prelogin.sh")
	postConnectPath = filepath.Join(homeBasePath, "postconnect.sh")
	preDownloadPath = filepath.Join(homeBasePath, "predownload.sh")
	preUploadPath = filepath.Join(homeBasePath, "preupload.sh")

	status := ftpd.GetStatus()
	if status.IsActive {
		logger.ErrorToConsole("ftpd is already active")
		os.Exit(1)
	}

	go func() {
		logger.Debug(logSender, "", "initializing FTP server with config %+v", ftpdConf)
		if err := ftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start FTP server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start SFTP server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := httpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start HTTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(ftpdConf.Bindings[0].GetAddress())
	waitTCPListening(httpdConf.Bindings[0].GetAddress())
	waitTCPListening(sftpdConf.Bindings[0].GetAddress())
	ftpd.ReloadCertificateMgr() //nolint:errcheck

	ftpdConf = config.GetFTPDConfig()
	ftpdConf.Bindings = []ftpd.Binding{
		{
			Port:    2124,
			TLSMode: 2,
		},
	}
	ftpdConf.CertificateFile = certPath
	ftpdConf.CertificateKeyFile = keyPath
	ftpdConf.CACertificates = []string{caCrtPath}
	ftpdConf.CARevocationLists = []string{caCRLPath}
	ftpdConf.EnableSite = false
	ftpdConf.DisableActiveMode = true
	ftpdConf.CombineSupport = 1
	ftpdConf.HASHSupport = 1

	go func() {
		logger.Debug(logSender, "", "initializing FTP server with config %+v", ftpdConf)
		if err := ftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start FTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(ftpdConf.Bindings[0].GetAddress())
	waitNoConnections()

	exitCode := m.Run()
	os.Remove(logFilePath)
	os.Remove(bannerFile)
	os.Remove(extAuthPath)
	os.Remove(preLoginPath)
	os.Remove(postConnectPath)
	os.Remove(preDownloadPath)
	os.Remove(preUploadPath)
	os.Remove(certPath)
	os.Remove(keyPath)
	os.Remove(caCrtPath)
	os.Remove(caCRLPath)
	os.Remove(hostKeyPath)
	os.Remove(hostKeyPath + ".pub")
	os.Exit(exitCode)
}

func TestInitializationFailure(t *testing.T) {
	ftpdConf := config.GetFTPDConfig()
	ftpdConf.Bindings = []ftpd.Binding{}
	ftpdConf.CertificateFile = filepath.Join(os.TempDir(), "test_ftpd.crt")
	ftpdConf.CertificateKeyFile = filepath.Join(os.TempDir(), "test_ftpd.key")
	err := ftpdConf.Initialize(configDir)
	require.EqualError(t, err, common.ErrNoBinding.Error())
	ftpdConf.Bindings = []ftpd.Binding{
		{
			Port: 0,
		},
		{
			Port: 2121,
		},
	}
	ftpdConf.BannerFile = "a-missing-file"
	err = ftpdConf.Initialize(configDir)
	require.Error(t, err)

	ftpdConf.BannerFile = ""
	ftpdConf.Bindings[1].TLSMode = 10
	err = ftpdConf.Initialize(configDir)
	require.Error(t, err)

	ftpdConf.CertificateFile = ""
	ftpdConf.CertificateKeyFile = ""
	ftpdConf.Bindings[1].TLSMode = 1
	err = ftpdConf.Initialize(configDir)
	require.Error(t, err)

	certPath := filepath.Join(os.TempDir(), "test_ftpd.crt")
	keyPath := filepath.Join(os.TempDir(), "test_ftpd.key")
	ftpdConf.CertificateFile = certPath
	ftpdConf.CertificateKeyFile = keyPath
	ftpdConf.CACertificates = []string{"invalid ca cert"}
	err = ftpdConf.Initialize(configDir)
	require.Error(t, err)

	ftpdConf.CACertificates = nil
	ftpdConf.CARevocationLists = []string{""}
	err = ftpdConf.Initialize(configDir)
	require.Error(t, err)

	ftpdConf.CACertificates = []string{caCrtPath}
	ftpdConf.CARevocationLists = []string{caCRLPath}
	ftpdConf.Bindings[1].ForcePassiveIP = "127001"
	err = ftpdConf.Initialize(configDir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "the provided passive IP \"127001\" is not valid")
	ftpdConf.Bindings[1].ForcePassiveIP = ""
	err = ftpdConf.Initialize(configDir)
	require.Error(t, err)
}

func TestBasicFTPHandling(t *testing.T) {
	u := getTestUser()
	u.QuotaSize = 6553600
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	u.QuotaSize = 6553600
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	for _, user := range []dataprovider.User{localUser, sftpUser} {
		client, err := getFTPClient(user, true, nil)
		if assert.NoError(t, err) {
			if user.Username == defaultUsername {
				assert.Len(t, common.Connections.GetStats(), 1)
			} else {
				assert.Len(t, common.Connections.GetStats(), 2)
			}
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(65535)
			expectedQuotaSize := testFileSize
			expectedQuotaFiles := 1
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)

			err = checkBasicFTP(client)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, path.Join("/missing_dir", testFileName), testFileSize, client, 0)
			assert.Error(t, err)
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)
			// overwrite an existing file
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)
			localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
			err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
			assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
			err = client.Rename(testFileName, testFileName+"1")
			assert.NoError(t, err)
			err = client.Delete(testFileName)
			assert.Error(t, err)
			err = client.Delete(testFileName + "1")
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
			assert.Equal(t, expectedQuotaSize-testFileSize, user.UsedQuotaSize)
			curDir, err := client.CurrentDir()
			if assert.NoError(t, err) {
				assert.Equal(t, "/", curDir)
			}
			testDir := "testDir"
			err = client.MakeDir(testDir)
			assert.NoError(t, err)
			err = client.ChangeDir(testDir)
			assert.NoError(t, err)
			curDir, err = client.CurrentDir()
			if assert.NoError(t, err) {
				assert.Equal(t, path.Join("/", testDir), curDir)
			}
			res, err := client.List(path.Join("/", testDir))
			assert.NoError(t, err)
			if assert.Len(t, res, 2) {
				assert.Equal(t, ".", res[0].Name)
				assert.Equal(t, "..", res[1].Name)
			}
			res, err = client.List(path.Join("/"))
			assert.NoError(t, err)
			if assert.Len(t, res, 2) {
				assert.Equal(t, ".", res[0].Name)
				assert.Equal(t, testDir, res[1].Name)
			}
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)
			size, err := client.FileSize(path.Join("/", testDir, testFileName))
			assert.NoError(t, err)
			assert.Equal(t, testFileSize, size)
			err = client.ChangeDirToParent()
			assert.NoError(t, err)
			curDir, err = client.CurrentDir()
			if assert.NoError(t, err) {
				assert.Equal(t, "/", curDir)
			}
			err = client.Delete(path.Join("/", testDir, testFileName))
			assert.NoError(t, err)
			err = client.Delete(testDir)
			assert.Error(t, err)
			err = client.RemoveDir(testDir)
			assert.NoError(t, err)

			err = os.Remove(testFilePath)
			assert.NoError(t, err)
			err = os.Remove(localDownloadPath)
			assert.NoError(t, err)
			err = client.Quit()
			assert.NoError(t, err)
		}
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 }, 1*time.Second, 50*time.Millisecond)
	assert.Eventually(t, func() bool { return common.Connections.GetClientConnections() == 0 }, 1000*time.Millisecond,
		50*time.Millisecond)
}

func TestStartDirectory(t *testing.T) {
	startDir := "/start/dir"
	u := getTestUser()
	u.Filters.StartDirectory = startDir
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	u.Filters.StartDirectory = startDir
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		client, err := getFTPClient(user, true, nil)
		if assert.NoError(t, err) {
			currentDir, err := client.CurrentDir()
			assert.NoError(t, err)
			assert.Equal(t, startDir, currentDir)

			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(65535)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)
			localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
			err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
			assert.NoError(t, err)
			entries, err := client.List(".")
			assert.NoError(t, err)
			assert.Len(t, entries, 3)

			entries, err = client.List("/")
			assert.NoError(t, err)
			assert.Len(t, entries, 2)

			err = client.ChangeDirToParent()
			assert.NoError(t, err)
			currentDir, err = client.CurrentDir()
			assert.NoError(t, err)
			assert.Equal(t, path.Dir(startDir), currentDir)
			err = client.ChangeDirToParent()
			assert.NoError(t, err)
			currentDir, err = client.CurrentDir()
			assert.NoError(t, err)
			assert.Equal(t, "/", currentDir)

			err = os.Remove(testFilePath)
			assert.NoError(t, err)
			err = os.Remove(localDownloadPath)
			assert.NoError(t, err)
			err = client.Quit()
			assert.NoError(t, err)
		}
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestMultiFactorAuth(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolFTP},
	}
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)

	user.Password = defaultPassword
	_, err = getFTPClient(user, true, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), dataprovider.ErrInvalidCredentials.Error())
	}
	passcode, err := generateTOTPPasscode(secret, otp.AlgorithmSHA1)
	assert.NoError(t, err)
	user.Password = defaultPassword + passcode
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}
	// reusing the same passcode should not work
	_, err = getFTPClient(user, true, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), dataprovider.ErrInvalidCredentials.Error())
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSecondFactorRequirement(t *testing.T) {
	u := getTestUser()
	u.Filters.TwoFactorAuthProtocols = []string{common.ProtocolFTP}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	_, err = getFTPClient(user, true, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "second factor authentication is not set")
	}

	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolFTP},
	}
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	passcode, err := generateTOTPPasscode(secret, otp.AlgorithmSHA1)
	assert.NoError(t, err)
	user.Password = defaultPassword + passcode
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginInvalidCredentials(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	user.Username = "wrong username"
	_, err = getFTPClient(user, false, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), dataprovider.ErrInvalidCredentials.Error())
	}
	user.Username = u.Username
	user.Password = "wrong pwd"
	_, err = getFTPClient(user, false, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), dataprovider.ErrInvalidCredentials.Error())
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestLoginNonExistentUser(t *testing.T) {
	user := getTestUser()
	_, err := getFTPClient(user, false, nil)
	assert.Error(t, err)
}

func TestLoginExternalAuth(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser()
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	client, err := getFTPClient(u, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}
	u.Username = defaultUsername + "1"
	client, err = getFTPClient(u, true, nil)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	}

	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, defaultUsername, user.Username)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	err = os.Remove(extAuthPath)
	assert.NoError(t, err)
}

func TestPreLoginHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser()
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(u, false), os.ModePerm)
	assert.NoError(t, err)
	providerConf.PreLoginHook = preLoginPath
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusNotFound)
	assert.NoError(t, err)
	client, err := getFTPClient(u, false, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)

	// test login with an existing user
	client, err = getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(user, true), os.ModePerm)
	assert.NoError(t, err)
	client, err = getFTPClient(u, false, nil)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	}
	user.Status = 0
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(user, false), os.ModePerm)
	assert.NoError(t, err)
	client, err = getFTPClient(u, false, nil)
	if !assert.Error(t, err, "pre-login script returned a disabled user, login must fail") {
		err := client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	err = os.Remove(preLoginPath)
	assert.NoError(t, err)
}

func TestPreDownloadHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	oldExecuteOn := common.Config.Actions.ExecuteOn
	oldHook := common.Config.Actions.Hook

	common.Config.Actions.ExecuteOn = []string{common.OperationPreDownload}
	common.Config.Actions.Hook = preDownloadPath

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(preDownloadPath, getExitCodeScriptContent(0), os.ModePerm)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	// now return an error from the pre-download hook
	err = os.WriteFile(preDownloadPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	client, err = getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "permission denied")
		}
		err := client.Quit()
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)

	common.Config.Actions.ExecuteOn = oldExecuteOn
	common.Config.Actions.Hook = oldHook
}

func TestPreUploadHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	oldExecuteOn := common.Config.Actions.ExecuteOn
	oldHook := common.Config.Actions.Hook

	common.Config.Actions.ExecuteOn = []string{common.OperationPreUpload}
	common.Config.Actions.Hook = preUploadPath

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(preUploadPath, getExitCodeScriptContent(0), os.ModePerm)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	// now return an error from the pre-upload hook
	err = os.WriteFile(preUploadPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	client, err = getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), ftpserver.ErrFileNameNotAllowed.Error())
		}
		err = ftpUploadFile(testFilePath, testFileName+"1", testFileSize, client, 0)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), ftpserver.ErrFileNameNotAllowed.Error())
		}
		err := client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)

	common.Config.Actions.ExecuteOn = oldExecuteOn
	common.Config.Actions.Hook = oldHook
}

func TestPostConnectHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	common.Config.PostConnectHook = postConnectPath

	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(postConnectPath, getExitCodeScriptContent(0), os.ModePerm)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}
	err = os.WriteFile(postConnectPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	client, err = getFTPClient(user, true, nil)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	}

	common.Config.PostConnectHook = "http://127.0.0.1:8079/healthz"

	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	common.Config.PostConnectHook = "http://127.0.0.1:8079/notfound"

	client, err = getFTPClient(user, true, nil)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.PostConnectHook = ""
}

//nolint:dupl
func TestMaxConnections(t *testing.T) {
	oldValue := common.Config.MaxTotalConnections
	common.Config.MaxTotalConnections = 1

	assert.Eventually(t, func() bool {
		return common.Connections.GetClientConnections() == 0
	}, 1000*time.Millisecond, 50*time.Millisecond)

	user := getTestUser()
	err := dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)
	user.Password = ""
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		_, err = getFTPClient(user, false, nil)
		assert.Error(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.MaxTotalConnections = oldValue
}

//nolint:dupl
func TestMaxPerHostConnections(t *testing.T) {
	oldValue := common.Config.MaxPerHostConnections
	common.Config.MaxPerHostConnections = 1

	assert.Eventually(t, func() bool {
		return common.Connections.GetClientConnections() == 0
	}, 1000*time.Millisecond, 50*time.Millisecond)

	user := getTestUser()
	err := dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)
	user.Password = ""
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		_, err = getFTPClient(user, false, nil)
		assert.Error(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.MaxPerHostConnections = oldValue
}

func TestRateLimiter(t *testing.T) {
	oldConfig := config.GetCommonConfig()

	cfg := config.GetCommonConfig()
	cfg.DefenderConfig.Enabled = true
	cfg.DefenderConfig.Threshold = 5
	cfg.DefenderConfig.ScoreLimitExceeded = 3
	cfg.RateLimitersConfig = []common.RateLimiterConfig{
		{
			Average:                1,
			Period:                 1000,
			Burst:                  1,
			Type:                   2,
			Protocols:              []string{common.ProtocolFTP},
			GenerateDefenderEvents: true,
			EntriesSoftLimit:       100,
			EntriesHardLimit:       150,
		},
	}

	err := common.Initialize(cfg, 0)
	assert.NoError(t, err)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	client, err := getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = getFTPClient(user, true, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "rate limit exceed")
	}

	_, err = getFTPClient(user, false, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "rate limit exceed")
	}

	_, err = getFTPClient(user, true, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "banned client IP")
	}

	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = common.Initialize(oldConfig, 0)
	assert.NoError(t, err)
}

func TestDefender(t *testing.T) {
	oldConfig := config.GetCommonConfig()

	cfg := config.GetCommonConfig()
	cfg.DefenderConfig.Enabled = true
	cfg.DefenderConfig.Threshold = 3
	cfg.DefenderConfig.ScoreLimitExceeded = 2

	err := common.Initialize(cfg, 0)
	assert.NoError(t, err)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}

	for i := 0; i < 3; i++ {
		user.Password = "wrong_pwd"
		_, err = getFTPClient(user, false, nil)
		assert.Error(t, err)
	}

	user.Password = defaultPassword
	_, err = getFTPClient(user, false, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "banned client IP")
	}

	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = common.Initialize(oldConfig, 0)
	assert.NoError(t, err)
}

func TestMaxSessions(t *testing.T) {
	u := getTestUser()
	u.MaxSessions = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		_, err = getFTPClient(user, false, nil)
		assert.Error(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestZeroBytesTransfers(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, useTLS := range []bool{true, false} {
		client, err := getFTPClient(user, useTLS, nil)
		if assert.NoError(t, err) {
			testFileName := "testfilename"
			err = checkBasicFTP(client)
			assert.NoError(t, err)
			localDownloadPath := filepath.Join(homeBasePath, "empty_download")
			err = os.WriteFile(localDownloadPath, []byte(""), os.ModePerm)
			assert.NoError(t, err)
			err = ftpUploadFile(localDownloadPath, testFileName, 0, client, 0)
			assert.NoError(t, err)
			size, err := client.FileSize(testFileName)
			assert.NoError(t, err)
			assert.Equal(t, int64(0), size)
			err = os.Remove(localDownloadPath)
			assert.NoError(t, err)
			assert.NoFileExists(t, localDownloadPath)
			err = ftpDownloadFile(testFileName, localDownloadPath, 0, client, 0)
			assert.NoError(t, err)
			assert.FileExists(t, localDownloadPath)
			err = client.Quit()
			assert.NoError(t, err)
			err = os.Remove(localDownloadPath)
			assert.NoError(t, err)
		}
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDownloadErrors(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 1
	subDir1 := "sub1"
	subDir2 := "sub2"
	u.Permissions[path.Join("/", subDir1)] = []string{dataprovider.PermListItems}
	u.Permissions[path.Join("/", subDir2)] = []string{dataprovider.PermListItems, dataprovider.PermUpload,
		dataprovider.PermDelete, dataprovider.PermDownload}
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/sub2",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{"*.jpg", "*.zip"},
		},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		testFilePath1 := filepath.Join(user.HomeDir, subDir1, "file.zip")
		testFilePath2 := filepath.Join(user.HomeDir, subDir2, "file.zip")
		testFilePath3 := filepath.Join(user.HomeDir, subDir2, "file.jpg")
		err = os.MkdirAll(filepath.Dir(testFilePath1), os.ModePerm)
		assert.NoError(t, err)
		err = os.MkdirAll(filepath.Dir(testFilePath2), os.ModePerm)
		assert.NoError(t, err)
		err = os.WriteFile(testFilePath1, []byte("file1"), os.ModePerm)
		assert.NoError(t, err)
		err = os.WriteFile(testFilePath2, []byte("file2"), os.ModePerm)
		assert.NoError(t, err)
		err = os.WriteFile(testFilePath3, []byte("file3"), os.ModePerm)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(path.Join("/", subDir1, "file.zip"), localDownloadPath, 5, client, 0)
		assert.Error(t, err)
		err = ftpDownloadFile(path.Join("/", subDir2, "file.zip"), localDownloadPath, 5, client, 0)
		assert.Error(t, err)
		err = ftpDownloadFile(path.Join("/", subDir2, "file.jpg"), localDownloadPath, 5, client, 0)
		assert.Error(t, err)
		err = ftpDownloadFile("/missing.zip", localDownloadPath, 5, client, 0)
		assert.Error(t, err)
		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadErrors(t *testing.T) {
	u := getTestUser()
	u.QuotaSize = 65535
	subDir1 := "sub1"
	subDir2 := "sub2"
	u.Permissions[path.Join("/", subDir1)] = []string{dataprovider.PermListItems}
	u.Permissions[path.Join("/", subDir2)] = []string{dataprovider.PermListItems, dataprovider.PermUpload,
		dataprovider.PermDelete}
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/sub2",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{"*.zip"},
		},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := user.QuotaSize
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = client.MakeDir(subDir1)
		assert.NoError(t, err)
		err = client.MakeDir(subDir2)
		assert.NoError(t, err)
		err = client.ChangeDir(subDir1)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.Error(t, err)
		err = client.ChangeDirToParent()
		assert.NoError(t, err)
		err = client.ChangeDir(subDir2)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName+".zip", testFileSize, client, 0)
		assert.Error(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.Error(t, err)
		err = client.ChangeDir("/")
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, subDir1, testFileSize, client, 0)
		assert.Error(t, err)
		// overquota
		err = ftpUploadFile(testFilePath, testFileName+"1", testFileSize, client, 0)
		assert.Error(t, err)
		err = client.Delete(path.Join("/", subDir2, testFileName))
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.Error(t, err)
		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSFTPBuffered(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	u.QuotaFiles = 100
	u.FsConfig.SFTPConfig.BufferSize = 2
	u.HomeDir = filepath.Join(os.TempDir(), u.Username)
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(sftpUser, true, nil)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		expectedQuotaSize := testFileSize
		expectedQuotaFiles := 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		// overwrite an existing file
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		user, _, err := httpdtest.GetUserByUsername(sftpUser.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)

		data := []byte("test data")
		err = os.WriteFile(testFilePath, data, os.ModePerm)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)), client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)+5), client, 5)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "operation unsupported")
		}
		err = ftpDownloadFile(testFileName, localDownloadPath, int64(4), client, 5)
		assert.NoError(t, err)
		readed, err := os.ReadFile(localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, []byte("data"), readed)
		// try to append to a file, it should fail
		// now append to a file
		srcFile, err := os.Open(testFilePath)
		if assert.NoError(t, err) {
			err = client.Append(testFileName, srcFile)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "operation unsupported")
			}
			err = srcFile.Close()
			assert.NoError(t, err)
			size, err := client.FileSize(testFileName)
			assert.NoError(t, err)
			assert.Equal(t, int64(len(data)), size)
			err = ftpDownloadFile(testFileName, localDownloadPath, int64(len(data)), client, 0)
			assert.NoError(t, err)
		}

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(sftpUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestResume(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		client, err := getFTPClient(user, true, nil)
		if assert.NoError(t, err) {
			testFilePath := filepath.Join(homeBasePath, testFileName)
			data := []byte("test data")
			err = os.WriteFile(testFilePath, data, os.ModePerm)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName, int64(len(data)), client, 0)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName, int64(len(data)+5), client, 5)
			assert.NoError(t, err)
			readed, err := os.ReadFile(filepath.Join(user.GetHomeDir(), testFileName))
			assert.NoError(t, err)
			assert.Equal(t, "test test data", string(readed))
			localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
			err = ftpDownloadFile(testFileName, localDownloadPath, int64(len(data)), client, 5)
			assert.NoError(t, err)
			readed, err = os.ReadFile(localDownloadPath)
			assert.NoError(t, err)
			assert.Equal(t, data, readed)
			err = client.Delete(testFileName)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName, int64(len(data)), client, 0)
			assert.NoError(t, err)
			// now append to a file
			srcFile, err := os.Open(testFilePath)
			if assert.NoError(t, err) {
				err = client.Append(testFileName, srcFile)
				assert.NoError(t, err)
				err = srcFile.Close()
				assert.NoError(t, err)
				size, err := client.FileSize(testFileName)
				assert.NoError(t, err)
				assert.Equal(t, int64(2*len(data)), size)
				err = ftpDownloadFile(testFileName, localDownloadPath, int64(2*len(data)), client, 0)
				assert.NoError(t, err)
				readed, err = os.ReadFile(localDownloadPath)
				assert.NoError(t, err)
				expected := append(data, data...)
				assert.Equal(t, expected, readed)
			}
			err = client.Quit()
			assert.NoError(t, err)
			err = os.Remove(testFilePath)
			assert.NoError(t, err)
			err = os.Remove(localDownloadPath)
			assert.NoError(t, err)
			if user.Username == defaultUsername {
				err = os.RemoveAll(user.GetHomeDir())
				assert.NoError(t, err)
				_, err = httpdtest.RemoveUser(user, http.StatusOK)
				assert.NoError(t, err)
				user.Password = defaultPassword
				user.ID = 0
				user.CreatedAt = 0
				_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
				assert.NoError(t, err, string(resp))
			}
		}
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestDeniedLoginMethod(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	_, err = getFTPClient(user, false, nil)
	assert.Error(t, err)
	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPublicKey, dataprovider.SSHLoginMethodKeyAndPassword}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		assert.NoError(t, checkBasicFTP(client))
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestDeniedProtocols(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedProtocols = []string{common.ProtocolFTP}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	_, err = getFTPClient(user, false, nil)
	assert.Error(t, err)
	user.Filters.DeniedProtocols = []string{common.ProtocolSSH, common.ProtocolWebDAV}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		assert.NoError(t, checkBasicFTP(client))
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaLimits(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 1
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	u.QuotaFiles = 1
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		testFileSize := int64(65535)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		testFileSize1 := int64(131072)
		testFileName1 := "test_file1.dat"
		testFilePath1 := filepath.Join(homeBasePath, testFileName1)
		err = createTestFile(testFilePath1, testFileSize1)
		assert.NoError(t, err)
		testFileSize2 := int64(32768)
		testFileName2 := "test_file2.dat"
		testFilePath2 := filepath.Join(homeBasePath, testFileName2)
		err = createTestFile(testFilePath2, testFileSize2)
		assert.NoError(t, err)
		// test quota files
		client, err := getFTPClient(user, false, nil)
		if assert.NoError(t, err) {
			err = ftpUploadFile(testFilePath, testFileName+".quota", testFileSize, client, 0)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName+".quota1", testFileSize, client, 0)
			assert.Error(t, err)
			err = client.Rename(testFileName+".quota", testFileName)
			assert.NoError(t, err)
			err = client.Quit()
			assert.NoError(t, err)
		}
		// test quota size
		user.QuotaSize = testFileSize - 1
		user.QuotaFiles = 0
		user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		client, err = getFTPClient(user, true, nil)
		if assert.NoError(t, err) {
			err = ftpUploadFile(testFilePath, testFileName+".quota", testFileSize, client, 0)
			assert.Error(t, err)
			err = client.Rename(testFileName, testFileName+".quota")
			assert.NoError(t, err)
			err = client.Quit()
			assert.NoError(t, err)
		}
		// now test quota limits while uploading the current file, we have 1 bytes remaining
		user.QuotaSize = testFileSize + 1
		user.QuotaFiles = 0
		user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		client, err = getFTPClient(user, false, nil)
		if assert.NoError(t, err) {
			err = ftpUploadFile(testFilePath1, testFileName1, testFileSize1, client, 0)
			assert.Error(t, err)
			_, err = client.FileSize(testFileName1)
			assert.Error(t, err)
			err = client.Rename(testFileName+".quota", testFileName)
			assert.NoError(t, err)
			// overwriting an existing file will work if the resulting size is lesser or equal than the current one
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath2, testFileName, testFileSize2, client, 0)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath1, testFileName, testFileSize1, client, 0)
			assert.Error(t, err)
			err = ftpUploadFile(testFilePath1, testFileName, testFileSize1, client, 10)
			assert.Error(t, err)
			err = ftpUploadFile(testFilePath2, testFileName, testFileSize2, client, 0)
			assert.NoError(t, err)
			err = client.Quit()
			assert.NoError(t, err)
		}

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
		err = os.Remove(testFilePath2)
		assert.NoError(t, err)
		if user.Username == defaultUsername {
			err = os.RemoveAll(user.GetHomeDir())
			assert.NoError(t, err)
			user.QuotaFiles = 0
			user.QuotaSize = 0
			_, err = httpdtest.RemoveUser(user, http.StatusOK)
			assert.NoError(t, err)
			user.Password = defaultPassword
			user.QuotaSize = 0
			user.ID = 0
			user.CreatedAt = 0
			_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
			assert.NoError(t, err, string(resp))
		}
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadMaxSize(t *testing.T) {
	testFileSize := int64(65535)
	u := getTestUser()
	u.Filters.MaxUploadFileSize = testFileSize + 1
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	u.Filters.MaxUploadFileSize = testFileSize + 1
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		testFileSize1 := int64(131072)
		testFileName1 := "test_file1.dat"
		testFilePath1 := filepath.Join(homeBasePath, testFileName1)
		err = createTestFile(testFilePath1, testFileSize1)
		assert.NoError(t, err)
		client, err := getFTPClient(user, false, nil)
		if assert.NoError(t, err) {
			err = ftpUploadFile(testFilePath1, testFileName1, testFileSize1, client, 0)
			assert.Error(t, err)
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)
			// now test overwrite an existing file with a size bigger than the allowed one
			err = createTestFile(filepath.Join(user.GetHomeDir(), testFileName1), testFileSize1)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath1, testFileName1, testFileSize1, client, 0)
			assert.Error(t, err)
			err = client.Quit()
			assert.NoError(t, err)
		}
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
		if user.Username == defaultUsername {
			err = os.RemoveAll(user.GetHomeDir())
			assert.NoError(t, err)
			_, err = httpdtest.RemoveUser(user, http.StatusOK)
			assert.NoError(t, err)
			user.Password = defaultPassword
			user.Filters.MaxUploadFileSize = 65536000
			user.ID = 0
			user.CreatedAt = 0
			_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
			assert.NoError(t, err, string(resp))
		}
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginWithIPilters(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedIP = []string{"192.167.0.0/24", "172.18.0.0/16"}
	u.Filters.AllowedIP = []string{"172.19.0.0/16"}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if !assert.Error(t, err) {
		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginWithDatabaseCredentials(t *testing.T) {
	u := getTestUser()
	u.FsConfig.Provider = sdk.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret(`{ "type": "service_account" }`)

	providerConf := config.GetProviderConf()
	providerConf.PreferDatabaseCredentials = true
	credentialsFile := filepath.Join(providerConf.CredentialsPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
	if !filepath.IsAbs(credentialsFile) {
		credentialsFile = filepath.Join(configDir, credentialsFile)
	}

	assert.NoError(t, dataprovider.Close())

	err := dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	if _, err = os.Stat(credentialsFile); err == nil {
		// remove the credentials file
		assert.NoError(t, os.Remove(credentialsFile))
	}

	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.GCSConfig.Credentials.GetStatus())
	assert.NotEmpty(t, user.FsConfig.GCSConfig.Credentials.GetPayload())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetAdditionalData())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetKey())

	assert.NoFileExists(t, credentialsFile)

	client, err := getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	assert.NoError(t, dataprovider.Close())
	assert.NoError(t, config.LoadConfig(configDir, ""))
	providerConf = config.GetProviderConf()
	assert.NoError(t, dataprovider.Initialize(providerConf, configDir, true))
}

func TestLoginInvalidFs(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.PreferDatabaseCredentials = false
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	u := getTestUser()
	u.FsConfig.Provider = sdk.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("invalid JSON for credentials")
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	providerConf = config.GetProviderConf()
	credentialsFile := filepath.Join(providerConf.CredentialsPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
	if !filepath.IsAbs(credentialsFile) {
		credentialsFile = filepath.Join(configDir, credentialsFile)
	}

	// now remove the credentials file so the filesystem creation will fail
	err = os.Remove(credentialsFile)
	assert.NoError(t, err)

	client, err := getFTPClient(user, false, nil)
	if !assert.Error(t, err) {
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestClientClose(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		stats := common.Connections.GetStats()
		if assert.Len(t, stats, 1) {
			common.Connections.Close(stats[0].ConnectionID)
			assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 },
				1*time.Second, 50*time.Millisecond)
		}
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRename(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		testDir := "adir"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		client, err := getFTPClient(user, false, nil)
		if assert.NoError(t, err) {
			err = checkBasicFTP(client)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)
			err = client.MakeDir(testDir)
			assert.NoError(t, err)
			err = client.Rename(testFileName, path.Join("missing", testFileName))
			assert.Error(t, err)
			err = client.Rename(testFileName, path.Join(testDir, testFileName))
			assert.NoError(t, err)
			size, err := client.FileSize(path.Join(testDir, testFileName))
			assert.NoError(t, err)
			assert.Equal(t, testFileSize, size)
			if runtime.GOOS != osWindows {
				otherDir := "dir"
				err = client.MakeDir(otherDir)
				assert.NoError(t, err)
				err = client.MakeDir(path.Join(otherDir, testDir))
				assert.NoError(t, err)
				code, response, err := client.SendCustomCommand(fmt.Sprintf("SITE CHMOD 0001 %v", otherDir))
				assert.NoError(t, err)
				assert.Equal(t, ftp.StatusCommandOK, code)
				assert.Equal(t, "SITE CHMOD command successful", response)
				err = client.Rename(testDir, path.Join(otherDir, testDir))
				assert.Error(t, err)

				code, response, err = client.SendCustomCommand(fmt.Sprintf("SITE CHMOD 755 %v", otherDir))
				assert.NoError(t, err)
				assert.Equal(t, ftp.StatusCommandOK, code)
				assert.Equal(t, "SITE CHMOD command successful", response)
			}
			err = client.Quit()
			assert.NoError(t, err)
		}
		user.Permissions[path.Join("/", testDir)] = []string{dataprovider.PermListItems}
		user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		client, err = getFTPClient(user, false, nil)
		if assert.NoError(t, err) {
			err = client.Rename(path.Join(testDir, testFileName), testFileName)
			assert.Error(t, err)
			err := client.Quit()
			assert.NoError(t, err)
		}

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		if user.Username == defaultUsername {
			err = os.RemoveAll(user.GetHomeDir())
			assert.NoError(t, err)
			_, err = httpdtest.RemoveUser(user, http.StatusOK)
			assert.NoError(t, err)
			user.Permissions = make(map[string][]string)
			user.Permissions["/"] = allPerms
			user.Password = defaultPassword
			user.ID = 0
			user.CreatedAt = 0
			_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
			assert.NoError(t, err, string(resp))
		}
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestSymlink(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		client, err := getFTPClient(user, false, nil)
		if assert.NoError(t, err) {
			err = checkBasicFTP(client)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)
			code, _, err := client.SendCustomCommand(fmt.Sprintf("SITE SYMLINK %v %v", testFileName, testFileName+".link"))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusCommandOK, code)

			if runtime.GOOS != osWindows {
				testDir := "adir"
				otherDir := "dir"
				err = client.MakeDir(otherDir)
				assert.NoError(t, err)
				err = client.MakeDir(path.Join(otherDir, testDir))
				assert.NoError(t, err)
				code, response, err := client.SendCustomCommand(fmt.Sprintf("SITE CHMOD 0001 %v", otherDir))
				assert.NoError(t, err)
				assert.Equal(t, ftp.StatusCommandOK, code)
				assert.Equal(t, "SITE CHMOD command successful", response)
				code, _, err = client.SendCustomCommand(fmt.Sprintf("SITE SYMLINK %v %v", testDir, path.Join(otherDir, testDir)))
				assert.NoError(t, err)
				assert.Equal(t, ftp.StatusFileUnavailable, code)

				code, response, err = client.SendCustomCommand(fmt.Sprintf("SITE CHMOD 755 %v", otherDir))
				assert.NoError(t, err)
				assert.Equal(t, ftp.StatusCommandOK, code)
				assert.Equal(t, "SITE CHMOD command successful", response)
			}
			err = client.Quit()
			assert.NoError(t, err)
			if user.Username == defaultUsername {
				err = os.RemoveAll(user.GetHomeDir())
				assert.NoError(t, err)
				_, err = httpdtest.RemoveUser(user, http.StatusOK)
				assert.NoError(t, err)
				user.Password = defaultPassword
				user.ID = 0
				user.CreatedAt = 0
				_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
				assert.NoError(t, err, string(resp))
			}
		}
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestStat(t *testing.T) {
	u := getTestUser()
	u.Permissions["/subdir"] = []string{dataprovider.PermUpload}
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)

	for _, user := range []dataprovider.User{localUser, sftpUser} {
		client, err := getFTPClient(user, false, nil)
		if assert.NoError(t, err) {
			subDir := "subdir"
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(65535)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = client.MakeDir(subDir)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, path.Join("/", subDir, testFileName), testFileSize, client, 0)
			assert.Error(t, err)
			size, err := client.FileSize(testFileName)
			assert.NoError(t, err)
			assert.Equal(t, testFileSize, size)
			_, err = client.FileSize(path.Join("/", subDir, testFileName))
			assert.Error(t, err)
			_, err = client.FileSize("missing file")
			assert.Error(t, err)
			err = client.Quit()
			assert.NoError(t, err)

			err = os.Remove(testFilePath)
			assert.NoError(t, err)
			if user.Username == defaultUsername {
				err = os.RemoveAll(user.GetHomeDir())
				assert.NoError(t, err)
				_, err = httpdtest.RemoveUser(user, http.StatusOK)
				assert.NoError(t, err)
				user.Password = defaultPassword
				user.ID = 0
				user.CreatedAt = 0
				_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
				assert.NoError(t, err, string(resp))
			}
		}
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadOverwriteVfolder(t *testing.T) {
	u := getTestUser()
	vdir := "/vdir"
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	folderName := filepath.Base(mappedPath)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: vdir,
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join(vdir, testFileName), testFileSize, client, 0)
		assert.NoError(t, err)
		folder, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, folder.UsedQuotaSize)
		assert.Equal(t, 1, folder.UsedQuotaFiles)
		err = ftpUploadFile(testFilePath, path.Join(vdir, testFileName), testFileSize, client, 0)
		assert.NoError(t, err)
		folder, _, err = httpdtest.GetFolderByName(folderName, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, folder.UsedQuotaSize)
		assert.Equal(t, 1, folder.UsedQuotaFiles)
		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestTransferQuotaLimits(t *testing.T) {
	u := getTestUser()
	u.DownloadDataTransfer = 1
	u.UploadDataTransfer = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(524288)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), ftpserver.ErrStorageExceeded.Error())
		}
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), common.ErrReadQuotaExceeded.Error())
		}
		err = client.Quit()
		assert.NoError(t, err)
	}

	testFileSize = int64(600000)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	user.DownloadDataTransfer = 2
	user.UploadDataTransfer = 2
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.Error(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.Error(t, err)

		err = client.Quit()
		assert.NoError(t, err)
	}

	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestAllocateAvailable(t *testing.T) {
	u := getTestUser()
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	folderName := filepath.Base(mappedPath)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: "/vdir",
		QuotaSize:   110,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("allo 2000000")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)

		code, response, err = client.SendCustomCommand("AVBL /vdir")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		assert.Equal(t, "110", response)

		code, _, err = client.SendCustomCommand("AVBL")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)

		err = client.Quit()
		assert.NoError(t, err)
	}
	user.QuotaSize = 100
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := user.QuotaSize - 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		code, response, err := client.SendCustomCommand("allo 1000")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)

		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)

		code, response, err = client.SendCustomCommand("AVBL")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		assert.Equal(t, "1", response)

		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	user.TotalDataTransfer = 1
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("AVBL")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		assert.Equal(t, "1", response)

		err = client.Quit()
		assert.NoError(t, err)
	}

	user.TotalDataTransfer = 0
	user.UploadDataTransfer = 5
	user.QuotaSize = 6 * 1024 * 1024
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("AVBL")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		assert.Equal(t, "5242880", response)

		err = client.Quit()
		assert.NoError(t, err)
	}

	user.TotalDataTransfer = 0
	user.UploadDataTransfer = 5
	user.QuotaSize = 0
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("AVBL")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		assert.Equal(t, "5242880", response)

		err = client.Quit()
		assert.NoError(t, err)
	}

	user.Filters.MaxUploadFileSize = 100
	user.QuotaSize = 0
	user.TotalDataTransfer = 0
	user.UploadDataTransfer = 0
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("allo 10000")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)

		code, response, err = client.SendCustomCommand("AVBL")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		assert.Equal(t, "100", response)

		err = client.Quit()
		assert.NoError(t, err)
	}

	user.QuotaSize = 50
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("AVBL")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		assert.Equal(t, "0", response)
	}

	user.QuotaSize = 1000
	user.Filters.MaxUploadFileSize = 1
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("AVBL")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		assert.Equal(t, "1", response)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestAvailableSFTPFs(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(sftpUser, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("AVBL /")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		avblSize, err := strconv.ParseInt(response, 10, 64)
		assert.NoError(t, err)
		assert.Greater(t, avblSize, int64(0))

		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestChtimes(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)

	for _, user := range []dataprovider.User{localUser, sftpUser} {
		client, err := getFTPClient(user, false, nil)
		if assert.NoError(t, err) {
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(65535)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = checkBasicFTP(client)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)

			mtime := time.Now().Format("20060102150405")
			code, response, err := client.SendCustomCommand(fmt.Sprintf("MFMT %v %v", mtime, testFileName))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusFile, code)
			assert.Equal(t, fmt.Sprintf("Modify=%v; %v", mtime, testFileName), response)
			err = client.Quit()
			assert.NoError(t, err)

			err = os.Remove(testFilePath)
			assert.NoError(t, err)
			if user.Username == defaultUsername {
				err = os.RemoveAll(user.GetHomeDir())
				assert.NoError(t, err)
				_, err = httpdtest.RemoveUser(user, http.StatusOK)
				assert.NoError(t, err)
				user.Password = defaultPassword
				user.ID = 0
				user.CreatedAt = 0
				_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
				assert.NoError(t, err, string(resp))
			}
		}
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestChown(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("chown is not supported on Windows")
	}
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(131072)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		code, response, err := client.SendCustomCommand(fmt.Sprintf("SITE CHOWN 1000:1000 %v", testFileName))
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFileUnavailable, code)
		assert.Equal(t, "Couldn't chown: operation unsupported", response)
		err = client.Quit()
		assert.NoError(t, err)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestChmod(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("chmod is partially supported on Windows")
	}
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		client, err := getFTPClient(user, true, nil)
		if assert.NoError(t, err) {
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(131072)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = checkBasicFTP(client)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)

			code, response, err := client.SendCustomCommand(fmt.Sprintf("SITE CHMOD 600 %v", testFileName))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusCommandOK, code)
			assert.Equal(t, "SITE CHMOD command successful", response)

			fi, err := os.Stat(filepath.Join(user.HomeDir, testFileName))
			if assert.NoError(t, err) {
				assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
			}
			err = client.Quit()
			assert.NoError(t, err)

			err = os.Remove(testFilePath)
			assert.NoError(t, err)
			if user.Username == defaultUsername {
				err = os.RemoveAll(user.GetHomeDir())
				assert.NoError(t, err)
				_, err = httpdtest.RemoveUser(user, http.StatusOK)
				assert.NoError(t, err)
				user.Password = defaultPassword
				user.ID = 0
				user.CreatedAt = 0
				_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
				assert.NoError(t, err, string(resp))
			}
		}
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestCombineDisabled(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		client, err := getFTPClient(user, true, nil)
		if assert.NoError(t, err) {
			err = checkBasicFTP(client)
			assert.NoError(t, err)

			code, response, err := client.SendCustomCommand("COMB file file.1 file.2")
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusNotImplemented, code)
			assert.Equal(t, "COMB support is disabled", response)

			err = client.Quit()
			assert.NoError(t, err)
		}
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestActiveModeDisabled(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClientImplicitTLS(user)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		code, response, err := client.SendCustomCommand("PORT 10,2,0,2,4,31")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusNotAvailable, code)
		assert.Equal(t, "PORT command is disabled", response)

		code, response, err = client.SendCustomCommand("EPRT |1|132.235.1.2|6275|")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusNotAvailable, code)
		assert.Equal(t, "EPRT command is disabled", response)

		err = client.Quit()
		assert.NoError(t, err)
	}

	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCustomCommand("PORT 10,2,0,2,4,31")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusBadArguments, code)
		assert.Equal(t, "Your request does not meet the configured security requirements", response)

		code, response, err = client.SendCustomCommand("EPRT |1|132.235.1.2|6275|")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusBadArguments, code)
		assert.Equal(t, "Your request does not meet the configured security requirements", response)

		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSITEDisabled(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClientImplicitTLS(user)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)

		code, response, err := client.SendCustomCommand("SITE CHMOD 600 afile.txt")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusBadCommand, code)
		assert.Equal(t, "SITE support is disabled", response)

		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestHASH(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)
	u = getTestUserWithCryptFs()
	u.Username += "_crypt"
	cryptUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser, cryptUser} {
		client, err := getFTPClientImplicitTLS(user)
		if assert.NoError(t, err) {
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(131072)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = checkBasicFTP(client)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)

			h := sha256.New()
			f, err := os.Open(testFilePath)
			assert.NoError(t, err)
			_, err = io.Copy(h, f)
			assert.NoError(t, err)
			hash := hex.EncodeToString(h.Sum(nil))
			err = f.Close()
			assert.NoError(t, err)

			code, response, err := client.SendCustomCommand(fmt.Sprintf("XSHA256 %v", testFileName))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusRequestedFileActionOK, code)
			assert.Contains(t, response, hash)

			code, response, err = client.SendCustomCommand(fmt.Sprintf("HASH %v", testFileName))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusFile, code)
			assert.Contains(t, response, hash)

			err = client.Quit()
			assert.NoError(t, err)

			err = os.Remove(testFilePath)
			assert.NoError(t, err)
			if user.Username == defaultUsername {
				err = os.RemoveAll(user.GetHomeDir())
				assert.NoError(t, err)
				_, err = httpdtest.RemoveUser(user, http.StatusOK)
				assert.NoError(t, err)
				user.Password = defaultPassword
				user.ID = 0
				user.CreatedAt = 0
				_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
				assert.NoError(t, err, string(resp))
			}
		}
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(cryptUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(cryptUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestCombine(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		client, err := getFTPClientImplicitTLS(user)
		if assert.NoError(t, err) {
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(131072)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = checkBasicFTP(client)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName+".1", testFileSize, client, 0)
			assert.NoError(t, err)
			err = ftpUploadFile(testFilePath, testFileName+".2", testFileSize, client, 0)
			assert.NoError(t, err)

			code, response, err := client.SendCustomCommand(fmt.Sprintf("COMB %v %v %v", testFileName, testFileName+".1", testFileName+".2"))
			assert.NoError(t, err)
			if user.Username == defaultUsername {
				assert.Equal(t, ftp.StatusRequestedFileActionOK, code)
				assert.Equal(t, "COMB succeeded!", response)
			} else {
				assert.Equal(t, ftp.StatusFileUnavailable, code)
				assert.Contains(t, response, "COMB is not supported for this filesystem")
			}

			err = client.Quit()
			assert.NoError(t, err)

			err = os.Remove(testFilePath)
			assert.NoError(t, err)
			if user.Username == defaultUsername {
				err = os.RemoveAll(user.GetHomeDir())
				assert.NoError(t, err)
				_, err = httpdtest.RemoveUser(user, http.StatusOK)
				assert.NoError(t, err)
				user.Password = defaultPassword
				user.ID = 0
				user.CreatedAt = 0
				_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
				assert.NoError(t, err, string(resp))
			}
		}
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestClientCertificateAuthRevokedCert(t *testing.T) {
	u := getTestUser()
	u.Username = tlsClient2Username
	u.Filters.TLSUsername = sdk.TLSUsernameCN
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // use this for tests only
		MinVersion:         tls.VersionTLS12,
	}
	tlsCert, err := tls.X509KeyPair([]byte(client2Crt), []byte(client2Key))
	assert.NoError(t, err)
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
	_, err = getFTPClient(user, true, tlsConfig)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "bad certificate")
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestClientCertificateAuth(t *testing.T) {
	u := getTestUser()
	u.Username = tlsClient1Username
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // use this for tests only
		MinVersion:         tls.VersionTLS12,
	}
	tlsCert, err := tls.X509KeyPair([]byte(client1Crt), []byte(client1Key))
	assert.NoError(t, err)
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
	// TLS username is not enabled, mutual TLS should fail
	_, err = getFTPClient(user, true, tlsConfig)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "login method password is not allowed")
	}

	user.Filters.TLSUsername = sdk.TLSUsernameCN
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, tlsConfig)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}

	// now use a valid certificate with a CN different from username
	u = getTestUser()
	u.Username = tlsClient2Username
	u.Filters.TLSUsername = sdk.TLSUsernameCN
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword}
	user2, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	_, err = getFTPClient(user2, true, tlsConfig)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "does not match username")
	}

	// now disable certificate authentication
	user.Filters.DeniedLoginMethods = append(user.Filters.DeniedLoginMethods, dataprovider.LoginMethodTLSCertificate,
		dataprovider.LoginMethodTLSCertificateAndPwd)
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = getFTPClient(user, true, tlsConfig)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "login method TLSCertificate+password is not allowed")
	}

	// disable FTP protocol
	user.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword}
	user.Filters.DeniedProtocols = append(user.Filters.DeniedProtocols, common.ProtocolFTP)
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = getFTPClient(user, true, tlsConfig)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "protocol FTP is not allowed")
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user2.GetHomeDir())
	assert.NoError(t, err)

	_, err = getFTPClient(user, true, tlsConfig)
	assert.Error(t, err)
}

func TestClientCertificateAndPwdAuth(t *testing.T) {
	u := getTestUser()
	u.Username = tlsClient1Username
	u.Filters.TLSUsername = sdk.TLSUsernameCN
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword, dataprovider.LoginMethodTLSCertificate}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // use this for tests only
		MinVersion:         tls.VersionTLS12,
	}
	tlsCert, err := tls.X509KeyPair([]byte(client1Crt), []byte(client1Key))
	assert.NoError(t, err)
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
	client, err := getFTPClient(user, true, tlsConfig)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = getFTPClient(user, true, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "login method password is not allowed")
	}
	user.Password = defaultPassword + "1"
	_, err = getFTPClient(user, true, tlsConfig)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid credentials")
	}

	tlsCert, err = tls.X509KeyPair([]byte(client2Crt), []byte(client2Key))
	assert.NoError(t, err)
	tlsConfig.Certificates = []tls.Certificate{tlsCert}
	_, err = getFTPClient(user, true, tlsConfig)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "bad certificate")
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestExternatAuthWithClientCert(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser()
	u.Username = tlsClient1Username
	u.Filters.DeniedLoginMethods = append(u.Filters.DeniedLoginMethods, dataprovider.LoginMethodPassword)
	u.Filters.TLSUsername = sdk.TLSUsernameCN
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 8
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	// external auth not called, auth scope is 8
	_, err = getFTPClient(u, true, nil)
	assert.Error(t, err)
	_, _, err = httpdtest.GetUserByUsername(u.Username, http.StatusNotFound)
	assert.NoError(t, err)

	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // use this for tests only
		MinVersion:         tls.VersionTLS12,
	}
	tlsCert, err := tls.X509KeyPair([]byte(client1Crt), []byte(client1Key))
	assert.NoError(t, err)
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
	client, err := getFTPClient(u, true, tlsConfig)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	user, _, err := httpdtest.GetUserByUsername(u.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, u.Username, user.Username)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	u.Username = tlsClient2Username
	_, err = getFTPClient(u, true, tlsConfig)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid credentials")
	}

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	err = os.Remove(extAuthPath)
	assert.NoError(t, err)
}

func TestPreLoginHookWithClientCert(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser()
	u.Username = tlsClient1Username
	u.Filters.DeniedLoginMethods = append(u.Filters.DeniedLoginMethods, dataprovider.LoginMethodPassword)
	u.Filters.TLSUsername = sdk.TLSUsernameCN
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(u, false), os.ModePerm)
	assert.NoError(t, err)
	providerConf.PreLoginHook = preLoginPath
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	_, _, err = httpdtest.GetUserByUsername(tlsClient1Username, http.StatusNotFound)
	assert.NoError(t, err)
	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // use this for tests only
		MinVersion:         tls.VersionTLS12,
	}
	tlsCert, err := tls.X509KeyPair([]byte(client1Crt), []byte(client1Key))
	assert.NoError(t, err)
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
	client, err := getFTPClient(u, true, tlsConfig)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	user, _, err := httpdtest.GetUserByUsername(tlsClient1Username, http.StatusOK)
	assert.NoError(t, err)

	// test login with an existing user
	client, err = getFTPClient(user, true, tlsConfig)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}

	u.Username = tlsClient2Username
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(u, false), os.ModePerm)
	assert.NoError(t, err)
	_, err = getFTPClient(u, true, tlsConfig)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "does not match username")
	}

	user2, _, err := httpdtest.GetUserByUsername(tlsClient2Username, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user2.GetHomeDir())
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	err = os.Remove(preLoginPath)
	assert.NoError(t, err)
}

func TestNestedVirtualFolders(t *testing.T) {
	u := getTestUser()
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	mappedPathCrypt := filepath.Join(os.TempDir(), "crypt")
	folderNameCrypt := filepath.Base(mappedPathCrypt)
	vdirCryptPath := "/vdir/crypt"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderNameCrypt,
			FsConfig: vfs.Filesystem{
				Provider: sdk.CryptedFilesystemProvider,
				CryptConfig: vfs.CryptFsConfig{
					Passphrase: kms.NewPlainSecret(defaultPassword),
				},
			},
			MappedPath: mappedPathCrypt,
		},
		VirtualPath: vdirCryptPath,
	})
	mappedPath := filepath.Join(os.TempDir(), "local")
	folderName := filepath.Base(mappedPath)
	vdirPath := "/vdir/local"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
	})
	mappedPathNested := filepath.Join(os.TempDir(), "nested")
	folderNameNested := filepath.Base(mappedPathNested)
	vdirNestedPath := "/vdir/crypt/nested"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderNameNested,
			MappedPath: mappedPathNested,
		},
		VirtualPath: vdirNestedPath,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(sftpUser, false, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)

		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join("/vdir", testFileName), testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(path.Join("/vdir", testFileName), localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join(vdirPath, testFileName), testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(path.Join(vdirPath, testFileName), localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join(vdirCryptPath, testFileName), testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(path.Join(vdirCryptPath, testFileName), localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join(vdirNestedPath, testFileName), testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(path.Join(vdirNestedPath, testFileName), localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)

		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderNameCrypt}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderNameNested}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPathCrypt)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPathNested)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 }, 1*time.Second, 50*time.Millisecond)
	assert.Eventually(t, func() bool { return common.Connections.GetClientConnections() == 0 }, 1000*time.Millisecond,
		50*time.Millisecond)
}

func checkBasicFTP(client *ftp.ServerConn) error {
	_, err := client.CurrentDir()
	if err != nil {
		return err
	}
	err = client.NoOp()
	if err != nil {
		return err
	}
	_, err = client.List(".")
	if err != nil {
		return err
	}
	return nil
}

func ftpUploadFile(localSourcePath string, remoteDestPath string, expectedSize int64, client *ftp.ServerConn, offset uint64) error {
	srcFile, err := os.Open(localSourcePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	if offset > 0 {
		err = client.StorFrom(remoteDestPath, srcFile, offset)
	} else {
		err = client.Stor(remoteDestPath, srcFile)
	}
	if err != nil {
		return err
	}
	if expectedSize > 0 {
		size, err := client.FileSize(remoteDestPath)
		if err != nil {
			return err
		}
		if size != expectedSize {
			return fmt.Errorf("uploaded file size does not match, actual: %v, expected: %v", size, expectedSize)
		}
	}
	return nil
}

func ftpDownloadFile(remoteSourcePath string, localDestPath string, expectedSize int64, client *ftp.ServerConn, offset uint64) error {
	downloadDest, err := os.Create(localDestPath)
	if err != nil {
		return err
	}
	defer downloadDest.Close()
	var r *ftp.Response
	if offset > 0 {
		r, err = client.RetrFrom(remoteSourcePath, offset)
	} else {
		r, err = client.Retr(remoteSourcePath)
	}
	if err != nil {
		return err
	}
	defer r.Close()

	written, err := io.Copy(downloadDest, r)
	if err != nil {
		return err
	}
	if written != expectedSize {
		return fmt.Errorf("downloaded file size does not match, actual: %v, expected: %v", written, expectedSize)
	}
	return nil
}

func getFTPClientImplicitTLS(user dataprovider.User) (*ftp.ServerConn, error) {
	ftpOptions := []ftp.DialOption{ftp.DialWithTimeout(5 * time.Second)}
	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // use this for tests only
		MinVersion:         tls.VersionTLS12,
	}
	ftpOptions = append(ftpOptions, ftp.DialWithTLS(tlsConfig))
	ftpOptions = append(ftpOptions, ftp.DialWithDisabledEPSV(true))
	client, err := ftp.Dial(ftpSrvAddrTLS, ftpOptions...)
	if err != nil {
		return nil, err
	}
	pwd := defaultPassword
	if user.Password != "" {
		pwd = user.Password
	}
	err = client.Login(user.Username, pwd)
	if err != nil {
		return nil, err
	}
	return client, err
}

func getFTPClient(user dataprovider.User, useTLS bool, tlsConfig *tls.Config) (*ftp.ServerConn, error) {
	ftpOptions := []ftp.DialOption{ftp.DialWithTimeout(5 * time.Second)}
	if useTLS {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{
				ServerName:         "localhost",
				InsecureSkipVerify: true, // use this for tests only
				MinVersion:         tls.VersionTLS12,
			}
		}
		ftpOptions = append(ftpOptions, ftp.DialWithExplicitTLS(tlsConfig))
	}
	client, err := ftp.Dial(ftpServerAddr, ftpOptions...)
	if err != nil {
		return nil, err
	}
	pwd := defaultPassword
	if user.Password != "" {
		pwd = user.Password
	}
	err = client.Login(user.Username, pwd)
	if err != nil {
		return nil, err
	}
	return client, err
}

func waitTCPListening(address string) {
	for {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			logger.WarnToConsole("tcp server %v not listening: %v", address, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		logger.InfoToConsole("tcp server %v now listening", address)
		conn.Close()
		break
	}
}

func waitNoConnections() {
	time.Sleep(50 * time.Millisecond)
	for len(common.Connections.GetStats()) > 0 {
		time.Sleep(50 * time.Millisecond)
	}
}

func getTestUser() dataprovider.User {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:       defaultUsername,
			Password:       defaultPassword,
			HomeDir:        filepath.Join(homeBasePath, defaultUsername),
			Status:         1,
			ExpirationDate: 0,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = allPerms
	return user
}

func getTestSFTPUser() dataprovider.User {
	u := getTestUser()
	u.Username = u.Username + "_sftp"
	u.FsConfig.Provider = sdk.SFTPFilesystemProvider
	u.FsConfig.SFTPConfig.Endpoint = sftpServerAddr
	u.FsConfig.SFTPConfig.Username = defaultUsername
	u.FsConfig.SFTPConfig.Password = kms.NewPlainSecret(defaultPassword)
	return u
}

func getExtAuthScriptContent(user dataprovider.User, nonJSONResponse bool, username string) []byte {
	extAuthContent := []byte("#!/bin/sh\n\n")
	extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("if test \"$SFTPGO_AUTHD_USERNAME\" = \"%v\"; then\n", user.Username))...)
	if len(username) > 0 {
		user.Username = username
	}
	u, _ := json.Marshal(user)
	if nonJSONResponse {
		extAuthContent = append(extAuthContent, []byte("echo 'text response'\n")...)
	} else {
		extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("echo '%v'\n", string(u)))...)
	}
	extAuthContent = append(extAuthContent, []byte("else\n")...)
	if nonJSONResponse {
		extAuthContent = append(extAuthContent, []byte("echo 'text response'\n")...)
	} else {
		extAuthContent = append(extAuthContent, []byte("echo '{\"username\":\"\"}'\n")...)
	}
	extAuthContent = append(extAuthContent, []byte("fi\n")...)
	return extAuthContent
}

func getPreLoginScriptContent(user dataprovider.User, nonJSONResponse bool) []byte {
	content := []byte("#!/bin/sh\n\n")
	if nonJSONResponse {
		content = append(content, []byte("echo 'text response'\n")...)
		return content
	}
	if len(user.Username) > 0 {
		u, _ := json.Marshal(user)
		content = append(content, []byte(fmt.Sprintf("echo '%v'\n", string(u)))...)
	}
	return content
}

func getExitCodeScriptContent(exitCode int) []byte {
	content := []byte("#!/bin/sh\n\n")
	content = append(content, []byte(fmt.Sprintf("exit %v", exitCode))...)
	return content
}

func createTestFile(path string, size int64) error {
	baseDir := filepath.Dir(path)
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		err = os.MkdirAll(baseDir, os.ModePerm)
		if err != nil {
			return err
		}
	}
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, os.ModePerm)
}

func writeCerts(certPath, keyPath, caCrtPath, caCRLPath string) error {
	err := os.WriteFile(certPath, []byte(ftpsCert), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing FTPS certificate: %v", err)
		return err
	}
	err = os.WriteFile(keyPath, []byte(ftpsKey), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing FTPS private key: %v", err)
		return err
	}
	err = os.WriteFile(caCrtPath, []byte(caCRT), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing FTPS CA crt: %v", err)
		return err
	}
	err = os.WriteFile(caCRLPath, []byte(caCRL), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing FTPS CRL: %v", err)
		return err
	}
	return nil
}

func generateTOTPPasscode(secret string, algo otp.Algorithm) (string, error) {
	return totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: algo,
	})
}
