package webdavd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/eikenb/pipeat"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/webdav"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	testFile   = "test_dav_file"
	webDavCert = `-----BEGIN CERTIFICATE-----
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
	webDavKey = `-----BEGIN EC PARAMETERS-----
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
	caKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
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
)

var (
	errWalkDir  = errors.New("err walk dir")
	errWalkFile = errors.New("err walk file")
)

// MockOsFs mockable OsFs
type MockOsFs struct {
	vfs.Fs
	err                     error
	isAtomicUploadSupported bool
	reader                  *pipeat.PipeReaderAt
}

// Name returns the name for the Fs implementation
func (fs *MockOsFs) Name() string {
	return "mockOsFs"
}

// Open returns nil
func (fs *MockOsFs) Open(name string, offset int64) (vfs.File, *pipeat.PipeReaderAt, func(), error) {
	return nil, fs.reader, nil, nil
}

// IsUploadResumeSupported returns true if resuming uploads is supported
func (*MockOsFs) IsUploadResumeSupported() bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported
func (fs *MockOsFs) IsAtomicUploadSupported() bool {
	return fs.isAtomicUploadSupported
}

// Remove removes the named file or (empty) directory.
func (fs *MockOsFs) Remove(name string, isDir bool) error {
	if fs.err != nil {
		return fs.err
	}
	return os.Remove(name)
}

// Rename renames (moves) source to target
func (fs *MockOsFs) Rename(source, target string) error {
	if fs.err != nil {
		return fs.err
	}
	return os.Rename(source, target)
}

// Walk returns a duplicate path for testing
func (fs *MockOsFs) Walk(root string, walkFn filepath.WalkFunc) error {
	if fs.err == errWalkDir {
		walkFn("fsdpath", vfs.NewFileInfo("dpath", true, 0, time.Now(), false), nil) //nolint:errcheck
		walkFn("fsdpath", vfs.NewFileInfo("dpath", true, 0, time.Now(), false), nil) //nolint:errcheck
		return nil
	}
	walkFn("fsfpath", vfs.NewFileInfo("fpath", false, 0, time.Now(), false), nil) //nolint:errcheck
	return fs.err
}

// GetMimeType returns the content type
func (fs *MockOsFs) GetMimeType(name string) (string, error) {
	return "application/custom-mime", nil
}

func newMockOsFs(err error, atomicUpload bool, connectionID, rootDir string, reader *pipeat.PipeReaderAt) vfs.Fs {
	return &MockOsFs{
		Fs:                      vfs.NewOsFs(connectionID, rootDir, ""),
		err:                     err,
		isAtomicUploadSupported: atomicUpload,
		reader:                  reader,
	}
}

func TestOrderDirsToRemove(t *testing.T) {
	user := dataprovider.User{}
	fs := vfs.NewOsFs("id", os.TempDir(), "")
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
		request:        nil,
	}
	dirsToRemove := []objectMapping{}

	orderedDirs := connection.orderDirsToRemove(fs, dirsToRemove)
	assert.Equal(t, len(dirsToRemove), len(orderedDirs))

	dirsToRemove = []objectMapping{
		{
			fsPath:      "dir1",
			virtualPath: "",
		},
	}
	orderedDirs = connection.orderDirsToRemove(fs, dirsToRemove)
	assert.Equal(t, len(dirsToRemove), len(orderedDirs))

	dirsToRemove = []objectMapping{
		{
			fsPath:      "dir1",
			virtualPath: "",
		},
		{
			fsPath:      "dir12",
			virtualPath: "",
		},
		{
			fsPath:      filepath.Join("dir1", "a", "b"),
			virtualPath: "",
		},
		{
			fsPath:      filepath.Join("dir1", "a"),
			virtualPath: "",
		},
	}

	orderedDirs = connection.orderDirsToRemove(fs, dirsToRemove)
	if assert.Equal(t, len(dirsToRemove), len(orderedDirs)) {
		assert.Equal(t, "dir12", orderedDirs[0].fsPath)
		assert.Equal(t, filepath.Join("dir1", "a", "b"), orderedDirs[1].fsPath)
		assert.Equal(t, filepath.Join("dir1", "a"), orderedDirs[2].fsPath)
		assert.Equal(t, "dir1", orderedDirs[3].fsPath)
	}
}

func TestUserInvalidParams(t *testing.T) {
	u := &dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "username",
			HomeDir:  "invalid",
		},
	}
	c := &Configuration{
		Bindings: []Binding{
			{
				Port: 9000,
			},
		},
	}

	server := webDavServer{
		config:  c,
		binding: c.Bindings[0],
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", u.Username), nil)
	assert.NoError(t, err)

	_, err = server.validateUser(u, req, dataprovider.LoginMethodPassword)
	if assert.Error(t, err) {
		assert.EqualError(t, err, fmt.Sprintf("cannot login user with invalid home dir: %#v", u.HomeDir))
	}

	req.TLS = &tls.ConnectionState{}
	writeLog(req, http.StatusOK, nil)
}

func TestRemoteAddress(t *testing.T) {
	remoteAddr1 := "100.100.100.100"
	remoteAddr2 := "172.172.172.172"

	c := &Configuration{
		Bindings: []Binding{
			{
				Port:         9000,
				ProxyAllowed: []string{remoteAddr2, "10.8.0.0/30"},
			},
		},
	}

	server := webDavServer{
		config:  c,
		binding: c.Bindings[0],
	}
	err := server.binding.parseAllowedProxy()
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.NoError(t, err)
	assert.Empty(t, req.RemoteAddr)

	req.Header.Set("True-Client-IP", remoteAddr1)
	ip := util.GetRealIP(req)
	assert.Equal(t, remoteAddr1, ip)
	req.Header.Del("True-Client-IP")
	req.Header.Set("CF-Connecting-IP", remoteAddr1)
	ip = util.GetRealIP(req)
	assert.Equal(t, remoteAddr1, ip)
	req.Header.Del("CF-Connecting-IP")
	req.Header.Set("X-Forwarded-For", remoteAddr1)
	ip = util.GetRealIP(req)
	assert.Equal(t, remoteAddr1, ip)
	// this will be ignored, remoteAddr1 is not allowed to se this header
	req.Header.Set("X-Forwarded-For", remoteAddr2)
	req.RemoteAddr = remoteAddr1
	ip = server.checkRemoteAddress(req)
	assert.Equal(t, remoteAddr1, ip)
	req.RemoteAddr = ""
	ip = server.checkRemoteAddress(req)
	assert.Empty(t, ip)

	req.Header.Set("X-Forwarded-For", fmt.Sprintf("%v, %v", remoteAddr2, remoteAddr1))
	ip = util.GetRealIP(req)
	assert.Equal(t, remoteAddr2, ip)

	req.RemoteAddr = remoteAddr2
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("%v,%v", "12.34.56.78", "172.16.2.4"))
	ip = server.checkRemoteAddress(req)
	assert.Equal(t, "12.34.56.78", ip)
	assert.Equal(t, ip, req.RemoteAddr)

	req.RemoteAddr = "10.8.0.2"
	req.Header.Set("X-Forwarded-For", remoteAddr1)
	ip = server.checkRemoteAddress(req)
	assert.Equal(t, remoteAddr1, ip)
	assert.Equal(t, ip, req.RemoteAddr)

	req.RemoteAddr = "10.8.0.3"
	req.Header.Set("X-Forwarded-For", "not an ip")
	ip = server.checkRemoteAddress(req)
	assert.Equal(t, "10.8.0.3", ip)
	assert.Equal(t, ip, req.RemoteAddr)

	req.Header.Del("X-Forwarded-For")
	req.RemoteAddr = ""
	req.Header.Set("X-Real-IP", remoteAddr1)
	ip = util.GetRealIP(req)
	assert.Equal(t, remoteAddr1, ip)
	req.RemoteAddr = ""
}

func TestConnWithNilRequest(t *testing.T) {
	c := &Connection{}
	assert.Empty(t, c.GetClientVersion())
	assert.Empty(t, c.GetCommand())
	assert.Empty(t, c.GetRemoteAddress())
}

func TestResolvePathErrors(t *testing.T) {
	ctx := context.Background()
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: "invalid",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, "")
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}

	err := connection.Mkdir(ctx, "", os.ModePerm)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}

	err = connection.Rename(ctx, "oldName", "newName")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}

	_, err = connection.Stat(ctx, "name")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}

	err = connection.RemoveAll(ctx, "")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}

	_, err = connection.OpenFile(ctx, "", 0, os.ModePerm)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}

	if runtime.GOOS != "windows" {
		user.HomeDir = filepath.Clean(os.TempDir())
		connection.User = user
		fs := vfs.NewOsFs("connID", connection.User.HomeDir, "")
		subDir := "sub"
		testTxtFile := "file.txt"
		err = os.MkdirAll(filepath.Join(os.TempDir(), subDir, subDir), os.ModePerm)
		assert.NoError(t, err)
		err = os.WriteFile(filepath.Join(os.TempDir(), subDir, subDir, testTxtFile), []byte("content"), os.ModePerm)
		assert.NoError(t, err)
		err = os.Chmod(filepath.Join(os.TempDir(), subDir, subDir), 0001)
		assert.NoError(t, err)
		err = os.WriteFile(filepath.Join(os.TempDir(), testTxtFile), []byte("test content"), os.ModePerm)
		assert.NoError(t, err)
		err = connection.Rename(ctx, testTxtFile, path.Join(subDir, subDir, testTxtFile))
		if assert.Error(t, err) {
			assert.EqualError(t, err, common.ErrPermissionDenied.Error())
		}
		_, err = connection.putFile(fs, filepath.Join(connection.User.HomeDir, subDir, subDir, testTxtFile),
			path.Join(subDir, subDir, testTxtFile))
		if assert.Error(t, err) {
			assert.EqualError(t, err, common.ErrPermissionDenied.Error())
		}
		err = os.Chmod(filepath.Join(os.TempDir(), subDir, subDir), os.ModePerm)
		assert.NoError(t, err)
		err = os.RemoveAll(filepath.Join(os.TempDir(), subDir))
		assert.NoError(t, err)
		err = os.Remove(filepath.Join(os.TempDir(), testTxtFile))
		assert.NoError(t, err)
	}
}

func TestFileAccessErrors(t *testing.T) {
	ctx := context.Background()
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, "")
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}
	missingPath := "missing path"
	fsMissingPath := filepath.Join(user.HomeDir, missingPath)
	err := connection.RemoveAll(ctx, missingPath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}
	_, err = connection.getFile(fs, fsMissingPath, missingPath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}
	_, err = connection.getFile(fs, fsMissingPath, missingPath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}
	p := filepath.Join(user.HomeDir, "adir", missingPath)
	_, err = connection.handleUploadToNewFile(fs, p, p, path.Join("adir", missingPath))
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}
	_, err = connection.handleUploadToExistingFile(fs, p, p, 0, path.Join("adir", missingPath))
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}

	fs = newMockOsFs(nil, false, fs.ConnectionID(), user.HomeDir, nil)
	_, err = connection.handleUploadToExistingFile(fs, p, p, 0, path.Join("adir", missingPath))
	if assert.Error(t, err) {
		assert.EqualError(t, err, os.ErrNotExist.Error())
	}

	f, err := os.CreateTemp("", "temp")
	assert.NoError(t, err)
	err = f.Close()
	assert.NoError(t, err)
	davFile, err := connection.handleUploadToExistingFile(fs, f.Name(), f.Name(), 123, f.Name())
	if assert.NoError(t, err) {
		transfer := davFile.(*webDavFile)
		transfers := connection.GetTransfers()
		if assert.Equal(t, 1, len(transfers)) {
			assert.Equal(t, transfers[0].ID, transfer.GetID())
			assert.Equal(t, int64(123), transfer.InitialSize)
			err = transfer.Close()
			assert.NoError(t, err)
			assert.Equal(t, 0, len(connection.GetTransfers()))
		}
	}

	err = os.Remove(f.Name())
	assert.NoError(t, err)
}

func TestRemoveDirTree(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, "")
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}

	vpath := path.Join("adir", "missing")
	p := filepath.Join(user.HomeDir, "adir", "missing")
	err := connection.removeDirTree(fs, p, vpath)
	if assert.Error(t, err) {
		assert.True(t, os.IsNotExist(err))
	}

	fs = newMockOsFs(nil, false, "mockID", user.HomeDir, nil)
	err = connection.removeDirTree(fs, p, vpath)
	if assert.Error(t, err) {
		assert.True(t, os.IsNotExist(err), "unexpected error: %v", err)
	}

	errFake := errors.New("fake err")
	fs = newMockOsFs(errFake, false, "mockID", user.HomeDir, nil)
	err = connection.removeDirTree(fs, p, vpath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, errFake.Error())
	}

	fs = newMockOsFs(errWalkDir, true, "mockID", user.HomeDir, nil)
	err = connection.removeDirTree(fs, p, vpath)
	if assert.Error(t, err) {
		assert.True(t, os.IsPermission(err), "unexpected error: %v", err)
	}

	fs = newMockOsFs(errWalkFile, false, "mockID", user.HomeDir, nil)
	err = connection.removeDirTree(fs, p, vpath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, errWalkFile.Error())
	}

	connection.User.Permissions["/"] = []string{dataprovider.PermListItems}
	fs = newMockOsFs(nil, false, "mockID", user.HomeDir, nil)
	err = connection.removeDirTree(fs, p, vpath)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrPermissionDenied.Error())
	}
}

func TestContentType(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, "")
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}
	testFilePath := filepath.Join(user.HomeDir, testFile)
	ctx := context.Background()
	baseTransfer := common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	fs = newMockOsFs(nil, false, fs.ConnectionID(), user.GetHomeDir(), nil)
	err := os.WriteFile(testFilePath, []byte(""), os.ModePerm)
	assert.NoError(t, err)
	davFile := newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = fs
	fi, err := davFile.Stat()
	if assert.NoError(t, err) {
		ctype, err := fi.(*webDavFileInfo).ContentType(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "application/custom-mime", ctype)
	}
	_, err = davFile.Readdir(-1)
	assert.Error(t, err)
	err = davFile.Close()
	assert.NoError(t, err)

	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = vfs.NewOsFs("id", user.HomeDir, "")
	fi, err = davFile.Stat()
	if assert.NoError(t, err) {
		ctype, err := fi.(*webDavFileInfo).ContentType(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/plain; charset=utf-8", ctype)
	}
	err = davFile.Close()
	assert.NoError(t, err)

	fi.(*webDavFileInfo).fsPath = "missing"
	_, err = fi.(*webDavFileInfo).ContentType(ctx)
	assert.EqualError(t, err, webdav.ErrNotImplemented.Error())

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
}

func TestTransferReadWriteErrors(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, "")
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}
	testFilePath := filepath.Join(user.HomeDir, testFile)
	baseTransfer := common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferUpload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	davFile := newWebDavFile(baseTransfer, nil, nil)
	p := make([]byte, 1)
	_, err := davFile.Read(p)
	assert.EqualError(t, err, common.ErrOpUnsupported.Error())

	r, w, err := pipeat.Pipe()
	assert.NoError(t, err)
	davFile = newWebDavFile(baseTransfer, nil, r)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)
	davFile = newWebDavFile(baseTransfer, vfs.NewPipeWriter(w), nil)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)
	err = r.Close()
	assert.NoError(t, err)
	err = w.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	_, err = davFile.Read(p)
	assert.True(t, os.IsNotExist(err))
	_, err = davFile.Stat()
	assert.True(t, os.IsNotExist(err))

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	err = os.WriteFile(testFilePath, []byte(""), os.ModePerm)
	assert.NoError(t, err)
	f, err := os.Open(testFilePath)
	if assert.NoError(t, err) {
		err = f.Close()
		assert.NoError(t, err)
	}
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.reader = f
	err = davFile.Close()
	assert.EqualError(t, err, common.ErrGenericFailure.Error())
	err = davFile.Close()
	assert.EqualError(t, err, common.ErrTransferClosed.Error())
	_, err = davFile.Read(p)
	assert.Error(t, err)
	info, err := davFile.Stat()
	if assert.NoError(t, err) {
		assert.Equal(t, int64(0), info.Size())
	}

	r, w, err = pipeat.Pipe()
	assert.NoError(t, err)
	mockFs := newMockOsFs(nil, false, fs.ConnectionID(), user.HomeDir, r)
	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, mockFs, dataprovider.TransferQuota{})
	davFile = newWebDavFile(baseTransfer, nil, nil)

	writeContent := []byte("content\r\n")
	go func() {
		n, err := w.Write(writeContent)
		assert.NoError(t, err)
		assert.Equal(t, len(writeContent), n)
		err = w.Close()
		assert.NoError(t, err)
	}()

	p = make([]byte, 64)
	n, err := davFile.Read(p)
	assert.EqualError(t, err, io.EOF.Error())
	assert.Equal(t, len(writeContent), n)
	err = davFile.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.writer = f
	err = davFile.Close()
	assert.EqualError(t, err, common.ErrGenericFailure.Error())

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
}

func TestTransferSeek(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, "")
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}
	testFilePath := filepath.Join(user.HomeDir, testFile)
	testFileContents := []byte("content")
	baseTransfer := common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferUpload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})
	davFile := newWebDavFile(baseTransfer, nil, nil)
	_, err := davFile.Seek(0, io.SeekStart)
	assert.EqualError(t, err, common.ErrOpUnsupported.Error())
	err = davFile.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	_, err = davFile.Seek(0, io.SeekCurrent)
	assert.True(t, os.IsNotExist(err))
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	err = os.WriteFile(testFilePath, testFileContents, os.ModePerm)
	assert.NoError(t, err)
	f, err := os.Open(testFilePath)
	if assert.NoError(t, err) {
		err = f.Close()
		assert.NoError(t, err)
	}
	baseTransfer = common.NewBaseTransfer(f, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	_, err = davFile.Seek(0, io.SeekStart)
	assert.Error(t, err)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	res, err := davFile.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), res)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	davFile = newWebDavFile(baseTransfer, nil, nil)
	res, err = davFile.Seek(0, io.SeekEnd)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(testFileContents)), res)
	err = davFile.updateStatInfo()
	assert.Nil(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath+"1", testFilePath+"1", testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	_, err = davFile.Seek(0, io.SeekEnd)
	assert.True(t, os.IsNotExist(err))
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.reader = f
	davFile.Fs = newMockOsFs(nil, true, fs.ConnectionID(), user.GetHomeDir(), nil)
	res, err = davFile.Seek(2, io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), res)

	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = newMockOsFs(nil, true, fs.ConnectionID(), user.GetHomeDir(), nil)
	res, err = davFile.Seek(2, io.SeekEnd)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), res)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath+"1", testFilePath+"1", testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})

	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = newMockOsFs(nil, true, fs.ConnectionID(), user.GetHomeDir(), nil)
	res, err = davFile.Seek(2, io.SeekEnd)
	assert.True(t, os.IsNotExist(err))
	assert.Equal(t, int64(0), res)

	assert.Len(t, common.Connections.GetStats(), 0)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
}

func TestBasicUsersCache(t *testing.T) {
	username := "webdav_internal_test"
	password := "pwd"
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:       username,
			Password:       password,
			HomeDir:        filepath.Join(os.TempDir(), username),
			Status:         1,
			ExpirationDate: 0,
		},
	}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	err := dataprovider.AddUser(&u, "", "")
	assert.NoError(t, err)
	user, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)

	c := &Configuration{
		Bindings: []Binding{
			{
				Port: 9000,
			},
		},
		Cache: Cache{
			Users: UsersCacheConfig{
				MaxSize:        50,
				ExpirationTime: 1,
			},
		},
	}
	dataprovider.InitializeWebDAVUserCache(c.Cache.Users.MaxSize)
	server := webDavServer{
		config:  c,
		binding: c.Bindings[0],
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user.Username), nil)
	assert.NoError(t, err)

	ipAddr := "127.0.0.1"

	_, _, _, _, err = server.authenticate(req, ipAddr) //nolint:dogsled
	assert.Error(t, err)

	now := time.Now()
	req.SetBasicAuth(username, password)
	_, isCached, _, loginMethod, err := server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMethod)
	// now the user should be cached
	cachedUser, ok := dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		assert.False(t, cachedUser.IsExpired())
		assert.True(t, cachedUser.Expiration.After(now.Add(time.Duration(c.Cache.Users.ExpirationTime)*time.Minute)))
		// authenticate must return the cached user now
		authUser, isCached, _, _, err := server.authenticate(req, ipAddr)
		assert.NoError(t, err)
		assert.True(t, isCached)
		assert.Equal(t, cachedUser.User, authUser)
	}
	// a wrong password must fail
	req.SetBasicAuth(username, "wrong")
	_, _, _, _, err = server.authenticate(req, ipAddr) //nolint:dogsled
	assert.EqualError(t, err, dataprovider.ErrInvalidCredentials.Error())
	req.SetBasicAuth(username, password)

	// force cached user expiration
	cachedUser.Expiration = now
	dataprovider.CacheWebDAVUser(cachedUser)
	cachedUser, ok = dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		assert.True(t, cachedUser.IsExpired())
	}
	// now authenticate should get the user from the data provider and update the cache
	_, isCached, _, loginMethod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMethod)
	cachedUser, ok = dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		assert.False(t, cachedUser.IsExpired())
	}
	// cache is not invalidated after a user modification if the fs does not change
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.True(t, ok)
	folderName := "testFolder"
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: filepath.Join(os.TempDir(), "mapped"),
		},
		VirtualPath: "/vdir",
	})

	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.False(t, ok)

	_, isCached, _, loginMethod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMethod)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.True(t, ok)
	// cache is invalidated after user deletion
	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.False(t, ok)

	err = dataprovider.DeleteFolder(folderName, "", "")
	assert.NoError(t, err)

	err = os.RemoveAll(u.GetHomeDir())
	assert.NoError(t, err)
}

func TestCachedUserWithFolders(t *testing.T) {
	username := "webdav_internal_folder_test"
	password := "dav_pwd"
	folderName := "test_folder"
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:       username,
			Password:       password,
			HomeDir:        filepath.Join(os.TempDir(), username),
			Status:         1,
			ExpirationDate: 0,
		},
	}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: filepath.Join(os.TempDir(), folderName),
		},
		VirtualPath: "/vpath",
	})
	err := dataprovider.AddUser(&u, "", "")
	assert.NoError(t, err)
	user, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)

	c := &Configuration{
		Bindings: []Binding{
			{
				Port: 9000,
			},
		},
		Cache: Cache{
			Users: UsersCacheConfig{
				MaxSize:        50,
				ExpirationTime: 1,
			},
		},
	}
	dataprovider.InitializeWebDAVUserCache(c.Cache.Users.MaxSize)
	server := webDavServer{
		config:  c,
		binding: c.Bindings[0],
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user.Username), nil)
	assert.NoError(t, err)

	ipAddr := "127.0.0.1"

	_, _, _, _, err = server.authenticate(req, ipAddr) //nolint:dogsled
	assert.Error(t, err)

	now := time.Now()
	req.SetBasicAuth(username, password)
	_, isCached, _, loginMethod, err := server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMethod)
	// now the user should be cached
	cachedUser, ok := dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		assert.False(t, cachedUser.IsExpired())
		assert.True(t, cachedUser.Expiration.After(now.Add(time.Duration(c.Cache.Users.ExpirationTime)*time.Minute)))
		// authenticate must return the cached user now
		authUser, isCached, _, _, err := server.authenticate(req, ipAddr)
		assert.NoError(t, err)
		assert.True(t, isCached)
		assert.Equal(t, cachedUser.User, authUser)
	}

	folder, err := dataprovider.GetFolderByName(folderName)
	assert.NoError(t, err)
	// updating a used folder should invalidate the cache only if the fs changed
	err = dataprovider.UpdateFolder(&folder, folder.Users, "", "")
	assert.NoError(t, err)

	_, isCached, _, loginMethod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.True(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMethod)
	cachedUser, ok = dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		assert.False(t, cachedUser.IsExpired())
	}
	// changing the folder path should invalidate the cache
	folder.MappedPath = filepath.Join(os.TempDir(), "anotherpath")
	err = dataprovider.UpdateFolder(&folder, folder.Users, "", "")
	assert.NoError(t, err)
	_, isCached, _, loginMethod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMethod)
	cachedUser, ok = dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		assert.False(t, cachedUser.IsExpired())
	}

	err = dataprovider.DeleteFolder(folderName, "", "")
	assert.NoError(t, err)
	// removing a used folder should invalidate the cache
	_, isCached, _, loginMethod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMethod)
	cachedUser, ok = dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		assert.False(t, cachedUser.IsExpired())
	}

	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.False(t, ok)

	err = os.RemoveAll(u.GetHomeDir())
	assert.NoError(t, err)

	err = os.RemoveAll(folder.MappedPath)
	assert.NoError(t, err)
}

func TestUsersCacheSizeAndExpiration(t *testing.T) {
	username := "webdav_internal_test"
	password := "pwd"
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir:        filepath.Join(os.TempDir(), username),
			Status:         1,
			ExpirationDate: 0,
		},
	}
	u.Username = username + "1"
	u.Password = password + "1"
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	err := dataprovider.AddUser(&u, "", "")
	assert.NoError(t, err)
	user1, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	u.Username = username + "2"
	u.Password = password + "2"
	err = dataprovider.AddUser(&u, "", "")
	assert.NoError(t, err)
	user2, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	u.Username = username + "3"
	u.Password = password + "3"
	err = dataprovider.AddUser(&u, "", "")
	assert.NoError(t, err)
	user3, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	u.Username = username + "4"
	u.Password = password + "4"
	err = dataprovider.AddUser(&u, "", "")
	assert.NoError(t, err)
	user4, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)

	c := &Configuration{
		Bindings: []Binding{
			{
				Port: 9000,
			},
		},
		Cache: Cache{
			Users: UsersCacheConfig{
				MaxSize:        3,
				ExpirationTime: 1,
			},
		},
	}
	dataprovider.InitializeWebDAVUserCache(c.Cache.Users.MaxSize)
	server := webDavServer{
		config:  c,
		binding: c.Bindings[0],
	}

	ipAddr := "127.0.1.1"
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user1.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user1.Username, password+"1")
	_, isCached, _, loginMehod, err := server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMehod)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user2.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user2.Username, password+"2")
	_, isCached, _, loginMehod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMehod)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user3.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user3.Username, password+"3")
	_, isCached, _, loginMehod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMehod)

	// the first 3 users are now cached
	_, ok := dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.True(t, ok)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user4.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user4.Username, password+"4")
	_, isCached, _, loginMehod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMehod)
	// user1, the first cached, should be removed now
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.False(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user4.Username)
	assert.True(t, ok)

	// a sleep ensures that expiration times are different
	time.Sleep(20 * time.Millisecond)
	// user1 logins, user2 should be removed
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user1.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user1.Username, password+"1")
	_, isCached, _, loginMehod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMehod)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.False(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user4.Username)
	assert.True(t, ok)

	// a sleep ensures that expiration times are different
	time.Sleep(20 * time.Millisecond)
	// user2 logins, user3 should be removed
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user2.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user2.Username, password+"2")
	_, isCached, _, loginMehod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMehod)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.False(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user4.Username)
	assert.True(t, ok)

	// a sleep ensures that expiration times are different
	time.Sleep(20 * time.Millisecond)
	// user3 logins, user4 should be removed
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user3.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user3.Username, password+"3")
	_, isCached, _, loginMehod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMehod)
	_, ok = dataprovider.GetCachedWebDAVUser(user4.Username)
	assert.False(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.True(t, ok)

	// now remove user1 after an update
	user1.HomeDir += "_mod"
	err = dataprovider.UpdateUser(&user1, "", "")
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.False(t, ok)

	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user4.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user4.Username, password+"4")
	_, isCached, _, loginMehod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMehod)

	// a sleep ensures that expiration times are different
	time.Sleep(20 * time.Millisecond)
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("/%v", user1.Username), nil)
	assert.NoError(t, err)
	req.SetBasicAuth(user1.Username, password+"1")
	_, isCached, _, loginMehod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMehod)
	_, ok = dataprovider.GetCachedWebDAVUser(user2.Username)
	assert.False(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user1.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user3.Username)
	assert.True(t, ok)
	_, ok = dataprovider.GetCachedWebDAVUser(user4.Username)
	assert.True(t, ok)

	err = dataprovider.DeleteUser(user1.Username, "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(user2.Username, "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(user3.Username, "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(user4.Username, "", "")
	assert.NoError(t, err)

	err = os.RemoveAll(u.GetHomeDir())
	assert.NoError(t, err)
}

func TestUserCacheIsolation(t *testing.T) {
	dataprovider.InitializeWebDAVUserCache(10)
	username := "webdav_internal_cache_test"
	password := "dav_pwd"
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:       username,
			Password:       password,
			HomeDir:        filepath.Join(os.TempDir(), username),
			Status:         1,
			ExpirationDate: 0,
		},
	}
	u.Permissions = make(map[string][]string)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	err := dataprovider.AddUser(&u, "", "")
	assert.NoError(t, err)
	user, err := dataprovider.UserExists(u.Username)
	assert.NoError(t, err)
	cachedUser := &dataprovider.CachedUser{
		User:       user,
		Expiration: time.Now().Add(24 * time.Hour),
		Password:   password,
		LockSystem: webdav.NewMemLS(),
	}
	cachedUser.User.FsConfig.S3Config.AccessSecret = kms.NewPlainSecret("test secret")
	err = cachedUser.User.FsConfig.S3Config.AccessSecret.Encrypt()
	assert.NoError(t, err)
	dataprovider.CacheWebDAVUser(cachedUser)
	cachedUser, ok := dataprovider.GetCachedWebDAVUser(username)

	if assert.True(t, ok) {
		_, err = cachedUser.User.GetFilesystem("")
		assert.NoError(t, err)
		// the filesystem is now cached
	}
	cachedUser, ok = dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		assert.True(t, cachedUser.User.FsConfig.S3Config.AccessSecret.IsEncrypted())
		err = cachedUser.User.FsConfig.S3Config.AccessSecret.Decrypt()
		assert.NoError(t, err)
		cachedUser.User.FsConfig.Provider = sdk.S3FilesystemProvider
		_, err = cachedUser.User.GetFilesystem("")
		assert.Error(t, err, "we don't have to get the previously cached filesystem!")
	}
	cachedUser, ok = dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		assert.Equal(t, sdk.LocalFilesystemProvider, cachedUser.User.FsConfig.Provider)
		assert.False(t, cachedUser.User.FsConfig.S3Config.AccessSecret.IsEncrypted())
	}

	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.False(t, ok)
}

func TestRecoverer(t *testing.T) {
	c := &Configuration{
		Bindings: []Binding{
			{
				Port: 9000,
			},
		},
	}
	server := webDavServer{
		config:  c,
		binding: c.Bindings[0],
	}
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, nil)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestMimeCache(t *testing.T) {
	cache := mimeCache{
		maxSize:   0,
		mimeTypes: make(map[string]string),
	}
	cache.addMimeToCache(".zip", "application/zip")
	mtype := cache.getMimeFromCache(".zip")
	assert.Equal(t, "", mtype)
	cache.maxSize = 1
	cache.addMimeToCache(".zip", "application/zip")
	mtype = cache.getMimeFromCache(".zip")
	assert.Equal(t, "application/zip", mtype)
	cache.addMimeToCache(".jpg", "image/jpeg")
	mtype = cache.getMimeFromCache(".jpg")
	assert.Equal(t, "", mtype)
}

func TestVerifyTLSConnection(t *testing.T) {
	oldCertMgr := certMgr

	caCrlPath := filepath.Join(os.TempDir(), "testcrl.crt")
	certPath := filepath.Join(os.TempDir(), "test.crt")
	keyPath := filepath.Join(os.TempDir(), "test.key")
	err := os.WriteFile(caCrlPath, []byte(caCRL), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(certPath, []byte(webDavCert), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(webDavKey), os.ModePerm)
	assert.NoError(t, err)

	certMgr, err = common.NewCertManager(certPath, keyPath, "", "webdav_test")
	assert.NoError(t, err)

	certMgr.SetCARevocationLists([]string{caCrlPath})
	err = certMgr.LoadCRLs()
	assert.NoError(t, err)

	crt, err := tls.X509KeyPair([]byte(client1Crt), []byte(client1Key))
	assert.NoError(t, err)
	x509crt, err := x509.ParseCertificate(crt.Certificate[0])
	assert.NoError(t, err)

	server := webDavServer{}
	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{x509crt},
	}

	err = server.verifyTLSConnection(state)
	assert.Error(t, err) // no verified certification chain

	crt, err = tls.X509KeyPair([]byte(caCRT), []byte(caKey))
	assert.NoError(t, err)

	x509CAcrt, err := x509.ParseCertificate(crt.Certificate[0])
	assert.NoError(t, err)

	state.VerifiedChains = append(state.VerifiedChains, []*x509.Certificate{x509crt, x509CAcrt})
	err = server.verifyTLSConnection(state)
	assert.NoError(t, err)

	crt, err = tls.X509KeyPair([]byte(client2Crt), []byte(client2Key))
	assert.NoError(t, err)
	x509crtRevoked, err := x509.ParseCertificate(crt.Certificate[0])
	assert.NoError(t, err)

	state.VerifiedChains = append(state.VerifiedChains, []*x509.Certificate{x509crtRevoked, x509CAcrt})
	state.PeerCertificates = []*x509.Certificate{x509crtRevoked}
	err = server.verifyTLSConnection(state)
	assert.EqualError(t, err, common.ErrCrtRevoked.Error())

	err = os.Remove(caCrlPath)
	assert.NoError(t, err)
	err = os.Remove(certPath)
	assert.NoError(t, err)
	err = os.Remove(keyPath)
	assert.NoError(t, err)

	certMgr = oldCertMgr
}

func TestMisc(t *testing.T) {
	oldCertMgr := certMgr

	certMgr = nil
	err := ReloadCertificateMgr()
	assert.Nil(t, err)
	val := getConfigPath("", ".")
	assert.Empty(t, val)

	certMgr = oldCertMgr
}
