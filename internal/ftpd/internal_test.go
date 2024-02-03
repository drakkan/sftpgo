// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package ftpd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/eikenb/pipeat"
	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/pires/go-proxyproto"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	ftpsCert = `-----BEGIN CERTIFICATE-----
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
QXV0aDAeFw0yNDAxMTAxODEyMDRaFw0zNDAxMTAxODIxNTRaMBMxETAPBgNVBAMT
CENlcnRBdXRoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7WHW216m
fi4uF8cx6HWf8wvAxaEWgCHTOi2MwFIzOrOtuT7xb64rkpdzx1aWetSiCrEyc3D1
v03k0Akvlz1gtnDtO64+MA8bqlTnCydZJY4cCTvDOBUYZgtMqHZzpE6xRrqQ84zh
yzjKQ5bR0st+XGfIkuhjSuf2n/ZPS37fge9j6AKzn/2uEVt33qmO85WtN3RzbSqL
CdOJ6cQ216j3la1C5+NWvzIKC7t6NE1bBGI4+tRj7B5P5MeamkkogwbExUjdHp3U
4yasvoGcCHUQDoa4Dej1faywz6JlwB6rTV4ys4aZDe67V/Q8iB2May1k7zBz1Ztb
KF5Em3xewP1LqPEowF1uc4KtPGcP4bxdaIpSpmObcn8AIfH6smLQrn0C3cs7CYfo
NlFuTbwzENUhjz0X6EsoM4w4c87lO+dRNR7YpHLqR/BJTbbyXUB0imne1u00fuzb
S7OtweiA9w7DRCkr2gU4lmHe7l0T+SA9pxIeVLb78x7ivdyXSF5LVQJ1JvhhWu6i
M6GQdLHat/0fpRFUbEe34RQSDJ2eOBifMJqvsvpBP8d2jcRZVUVrSXGc2mAGuGOY
/tmnCJGW8Fd+sgpCVAqM0pxCM+apqrvJYUqqQZ2ZxugCXULtRWJ9p4C9zUl40HEy
OQ+AaiiwFll/doXELglcJdNg8AZPGhugfxMCAwEAAaNFMEMwDgYDVR0PAQH/BAQD
AgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFNoJhIvDZQrEf/VQbWuu
XgNnt2m5MA0GCSqGSIb3DQEBCwUAA4ICAQCYhT5SRqk19hGrQ09hVSZOzynXAa5F
sYkEWJzFyLg9azhnTPE1bFM18FScnkd+dal6mt+bQiJvdh24NaVkDghVB7GkmXki
pAiZwEDHMqtbhiPxY8LtSeCBAz5JqXVU2Q0TpAgNSH4W7FbGWNThhxcJVOoIrXKE
jbzhwl1Etcaf0DBKWliUbdlxQQs65DLy+rNBYtOeK0pzhzn1vpehUlJ4eTFzP9KX
y2Mksuq9AspPbqnqpWW645MdTxMb5T57MCrY3GDKw63z5z3kz88LWJF3nOxZmgQy
WFUhbLmZm7x6N5eiu6Wk8/B4yJ/n5UArD4cEP1i7nqu+mbbM/SZlq1wnGpg/sbRV
oUF+a7pRcSbfxEttle4pLFhS+ErKatjGcNEab2OlU3bX5UoBs+TYodnCWGKOuBKV
L/CYc65QyeYZ+JiwYn9wC8YkzOnnVIQjiCEkLgSL30h9dxpnTZDLrdAA8ItelDn5
DvjuQq58CGDsaVqpSobiSC1DMXYWot4Ets1wwovUNEq1l0MERB+2olE+JU/8E23E
eL1/aA7Kw/JibkWz1IyzClpFDKXf6kR2onJyxerdwUL+is7tqYFLysiHxZDL1bli
SXbW8hMa5gvo0IilFP9Rznn8PplIfCsvBDVv6xsRr5nTAFtwKaMBVgznE2ghs69w
kK8u1YiiVenmoQ==
-----END CERTIFICATE-----`
	caKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
	caCRL = `-----BEGIN X509 CRL-----
MIICpzCBkAIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhDZXJ0QXV0aBcN
MjQwMTEwMTgyMjU4WhcNMjYwMTA5MTgyMjU4WjAkMCICEQDOaeHbjY4pEj8WBmqg
ZuRRFw0yNDAxMTAxODIyNThaoCMwITAfBgNVHSMEGDAWgBTaCYSLw2UKxH/1UG1r
rl4DZ7dpuTANBgkqhkiG9w0BAQsFAAOCAgEAZzZ4aBqCcAJigR9e/mqKpJa4B6FV
+jZmnWXolGeUuVkjdiG9w614x7mB2S768iioJyALejjCZjqsp6ydxtn0epQw4199
XSfPIxA9lxc7w79GLe0v3ztojvxDPh5V1+lwPzGf9i8AsGqb2BrcBqgxDeatndnE
jF+18bY1saXOBpukNLjtRScUXzy5YcSuO6mwz4548v+1ebpF7W4Yh+yh0zldJKcF
DouuirZWujJwTwxxfJ+2+yP7GAuefXUOhYs/1y9ylvUgvKFqSyokv6OaVgTooKYD
MSADzmNcbRvwyAC5oL2yJTVVoTFeP6fXl/BdFH3sO/hlKXGy4Wh1AjcVE6T0CSJ4
iYFX3gLFh6dbP9IQWMlIM5DKtAKSjmgOywEaWii3e4M0NFSf/Cy17p2E5/jXSLlE
ypDileK0aALkx2twGWwogh6sY1dQ6R3GpKSRPD2muQxVOG6wXvuJce0E9WLx1Ud4
hVUdUEMlKUvm77/15U5awarH2cCJQxzS/GMeIintQiG7hUlgRzRdmWVe3vOOvt94
cp8+ZUH/QSDOo41ATTHpFeC/XqF5E2G/ahXqra+O5my52V/FP0bSJnkorJ8apy67
sn6DFbkqX9khTXGtacczh2PcqVjcQjBniYl2sPO3qIrrrY3tic96tMnM/u3JRdcn
w7bXJGfJcIMrrKs=
-----END X509 CRL-----`
	client1Crt = `-----BEGIN CERTIFICATE-----
MIIEITCCAgmgAwIBAgIRAJr32nHRlhyPiS7IfZ/ZWYowDQYJKoZIhvcNAQELBQAw
EzERMA8GA1UEAxMIQ2VydEF1dGgwHhcNMjQwMTEwMTgxMjM3WhcNMzQwMTEwMTgy
MTUzWjASMRAwDgYDVQQDEwdjbGllbnQxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAtuQFiqvdjd8WLxP0FgPDyDEJ1/uJ+Aoj6QllNV7svWxwW+kiJ3X6
HUVNWhhCsNfly4pGW4erF4fZzmesElGx1PoWgQCWZKsa/N08bznelWgdmkyi85xE
OkTj6e/cTWHFSOBURNJaXkGHZ0ROSh7qu0Ld+eqNo3k9W+NqZaqYvs2K7MLWeYl7
Qie8Ctuq5Qaz/jm0XwR2PFBROVQSaCPCukancPQ21ftqHPhAbjxoxvvN5QP4ZdRf
XlH/LDLhlFnJzPZdHnVy9xisSPPRfFApJiwyfjRYdtslpJOcNgP6oPlpX/dybbhO
c9FEUgj/Q90Je8EfioBYFYsqVD6/dFv9SwIDAQABo3EwbzAOBgNVHQ8BAf8EBAMC
A7gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBRUh5Xo
Gzjh6iReaPSOgGatqOw9bDAfBgNVHSMEGDAWgBTaCYSLw2UKxH/1UG1rrl4DZ7dp
uTANBgkqhkiG9w0BAQsFAAOCAgEAyAK7cOTWqjyLgFM0kyyx1fNPvm2GwKep3MuU
OrSnLuWjoxzb7WcbKNVMlnvnmSUAWuErxsY0PUJNfcuqWiGmEp4d/SWfWPigG6DC
sDej35BlSfX8FCufYrfC74VNk4yBS2LVYmIqcpqUrfay0I2oZA8+ToLEpdUvEv2I
l59eOhJO2jsC3JbOyZZmK2Kv7d94fR+1tg2Rq1Wbnmc9AZKq7KDReAlIJh4u2KHb
BbtF79idusMwZyP777tqSQ4THBMa+VAEc2UrzdZqTIAwqlKQOvO2fRz2P+ARR+Tz
MYJMdCdmPZ9qAc8U1OcFBG6qDDltO8wf/Nu/PsSI5LGCIhIuPPIuKfm0rRfTqCG7
QPQPWjRoXtGGhwjdIuWbX9fIB+c+NpAEKHgLtV+Rxj8s5IVxqG9a5TtU9VkfVXJz
J20naoz/G+vDsVINpd3kH0ziNvdrKfGRM5UgtnUOPCXB22fVmkIsMH2knI10CKK+
offI56NTkLRu00xvg98/wdukhkwIAxg6PQI/BHY5mdvoacEHHHdOhMq+GSAh7DDX
G8+HdbABM1ExkPnZLat15q706ztiuUpQv1C2DI8YviUVkMqCslj4cD4F8EFPo4kr
kvme0Cuc9Qlf7N5rjdV3cjwavhFx44dyXj9aesft2Q1okPiIqbGNpcjHcIRlj4Au
MU3Bo0A=
-----END CERTIFICATE-----`
	client1Key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtuQFiqvdjd8WLxP0FgPDyDEJ1/uJ+Aoj6QllNV7svWxwW+ki
J3X6HUVNWhhCsNfly4pGW4erF4fZzmesElGx1PoWgQCWZKsa/N08bznelWgdmkyi
85xEOkTj6e/cTWHFSOBURNJaXkGHZ0ROSh7qu0Ld+eqNo3k9W+NqZaqYvs2K7MLW
eYl7Qie8Ctuq5Qaz/jm0XwR2PFBROVQSaCPCukancPQ21ftqHPhAbjxoxvvN5QP4
ZdRfXlH/LDLhlFnJzPZdHnVy9xisSPPRfFApJiwyfjRYdtslpJOcNgP6oPlpX/dy
bbhOc9FEUgj/Q90Je8EfioBYFYsqVD6/dFv9SwIDAQABAoIBAFjSHK7gENVZxphO
hHg8k9ShnDo8eyDvK8l9Op3U3/yOsXKxolivvyx//7UFmz3vXDahjNHe7YScAXdw
eezbqBXa7xrvghqZzp2HhFYwMJ0210mcdncBKVFzK4ztZHxgQ0PFTqet0R19jZjl
X3A325/eNZeuBeOied4qb/24AD6JGc6A0J55f5/QUQtdwYwrL15iC/KZXDL90PPJ
CFJyrSzcXvOMEvOfXIFxhDVKRCppyIYXG7c80gtNC37I6rxxMNQ4mxjwUI2IVhxL
j+nZDu0JgRZ4NaGjOq2e79QxUVm/GG3z25XgmBFBrXkEVV+sCZE1VDyj6kQfv9FU
NhOrwGECgYEAzq47r/HwXifuGYBV/mvInFw3BNLrKry+iUZrJ4ms4g+LfOi0BAgf
sXsWXulpBo2YgYjFdO8G66f69GlB4B7iLscpABXbRtpDZEnchQpaF36/+4g3i8gB
Z29XHNDB8+7t4wbXvlSnLv1tZWey2fS4hPosc2YlvS87DMmnJMJqhs8CgYEA4oiB
LGQP6VNdX0Uigmh5fL1g1k95eC8GP1ylczCcIwsb2OkAq0MT7SHRXOlg3leEq4+g
mCHk1NdjkSYxDL2ZeTKTS/gy4p1jlcDa6Ilwi4pVvatNvu4o80EYWxRNNb1mAn67
T8TN9lzc6mEi+LepQM3nYJ3F+ZWTKgxH8uoJwMUCgYEArpumE1vbjUBAuEyi2eGn
RunlFW83fBCfDAxw5KM8anNlja5uvuU6GU/6s06QCxg+2lh5MPPrLdXpfukZ3UVa
Itjg+5B7gx1MSALaiY8YU7cibFdFThM3lHIM72wyH2ogkWcrh0GvSFSUQlJcWCSW
asmMGiYXBgBL697FFZomMyMCgYEAkAnp0JcDQwHd4gDsk2zoqnckBsDb5J5J46n+
DYNAFEww9bgZ08u/9MzG+cPu8xFE621U2MbcYLVfuuBE2ewIlPaij/COMmeO9Z59
0tPpOuDH6eTtd1SptxqR6P+8pEn8feOlKHBj4Z1kXqdK/EiTlwAVeep4Al2oCFls
ujkz4F0CgYAe8vHnVFHlWi16zAqZx4ZZZhNuqPtgFkvPg9LfyNTA4dz7F9xgtUaY
nXBPyCe/8NtgBfT79HkPiG3TM0xRZY9UZgsJKFtqAu5u4ManuWDnsZI9RK2QTLHe
yEbH5r3Dg3n9k/3GbjXFIWdU9UaYsdnSKHHtMw9ZODc14LaAogEQug==
-----END RSA PRIVATE KEY-----`
	// client 2 crt is revoked
	client2Crt = `-----BEGIN CERTIFICATE-----
MIIEITCCAgmgAwIBAgIRAM5p4duNjikSPxYGaqBm5FEwDQYJKoZIhvcNAQELBQAw
EzERMA8GA1UEAxMIQ2VydEF1dGgwHhcNMjQwMTEwMTgxMjUyWhcNMzQwMTEwMTgy
MTUzWjASMRAwDgYDVQQDEwdjbGllbnQyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEApNYpNZVmXZtAObpRRIuP2o/7z04H2E161vKZvJ3LSLlUTImVjm/b
Qe6DTNCUVLnzQuanmUlu2rUnN3lDSfYoBcJWbvC3y1OCPRkCjDV6KiYMA9TPkZua
eq6y3+bFFfEmyumsVEe0bSuzNHXCOIBT7PqYMdovECcwBh/RZCA5mqO5omEKh4LQ
cr6+sVVkvD3nsyx0Alz/kTLFqc0mVflmpJq+0BpdetHRg4n5vy/I/08jZ81PQAmT
A0kyl0Jh132JBGFdA8eyugPPP8n5edU4f3HXV/nR7XLwBrpSt8KgEg8cwfAu4Ic0
6tGzB0CH8lSGtU0tH2/cOlDuguDD7VvokQIDAQABo3EwbzAOBgNVHQ8BAf8EBAMC
A7gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBR5mf0f
Zjf8ZCGXqU2+45th7VkkLDAfBgNVHSMEGDAWgBTaCYSLw2UKxH/1UG1rrl4DZ7dp
uTANBgkqhkiG9w0BAQsFAAOCAgEARhFxNAouwbpEfN1M90+ao5rwyxEewerSoCCz
PQzeUZ66MA/FkS/tFUGgGGG+wERN+WLbe1cN6q/XFr0FSMLuUxLXDNV02oUL/FnY
xcyNLaZUZ0pP7sA+Hmx2AdTA6baIwQbyIY9RLAaz6hzo1YbI8yeis645F1bxgL2D
EP5kXa3Obv0tqWByMZtrmJPv3p0W5GJKXVDn51GR/E5KI7pliZX2e0LmMX9mxfPB
4sXFUggMHXxWMMSAmXPVsxC2KX6gMnajO7JUraTwuGm+6V371FzEX+UKXHI+xSvO
78TseTIYsBGLjeiA8UjkKlD3T9qsQm2mb2PlKyqjvIm4i2ilM0E2w4JZmd45b925
7q/QLV3NZ/zZMi6AMyULu28DWKfAx3RLKwnHWSFcR4lVkxQrbDhEUMhAhLAX+2+e
qc7qZm3dTabi7ZJiiOvYK/yNgFHa/XtZp5uKPB5tigPIa+34hbZF7s2/ty5X3O1N
f5Ardz7KNsxJjZIt6HvB28E/PPOvBqCKJc1Y08J9JbZi8p6QS1uarGoR7l7rT1Hv
/ZXkNTw2bw1VpcWdzDBLLVHYNnJmS14189LVk11PcJJpSmubwCqg+ZZULdgtVr3S
ANas2dgMPVwXhnAalgkcc+lb2QqaEz06axfbRGBsgnyqR5/koKCg1Hr0+vThHSsR
E0+r2+4=
-----END CERTIFICATE-----`
	client2Key = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEApNYpNZVmXZtAObpRRIuP2o/7z04H2E161vKZvJ3LSLlUTImV
jm/bQe6DTNCUVLnzQuanmUlu2rUnN3lDSfYoBcJWbvC3y1OCPRkCjDV6KiYMA9TP
kZuaeq6y3+bFFfEmyumsVEe0bSuzNHXCOIBT7PqYMdovECcwBh/RZCA5mqO5omEK
h4LQcr6+sVVkvD3nsyx0Alz/kTLFqc0mVflmpJq+0BpdetHRg4n5vy/I/08jZ81P
QAmTA0kyl0Jh132JBGFdA8eyugPPP8n5edU4f3HXV/nR7XLwBrpSt8KgEg8cwfAu
4Ic06tGzB0CH8lSGtU0tH2/cOlDuguDD7VvokQIDAQABAoIBAQCMnEeg9uXQmdvq
op4qi6bV+ZcDWvvkLwvHikFMnYpIaheYBpF2ZMKzdmO4xgCSWeFCQ4Hah8KxfHCM
qLuWvw2bBBE5J8yQ/JaPyeLbec7RX41GQ2YhPoxDdP0PdErREdpWo4imiFhH/Ewt
Rvq7ufRdpdLoS8dzzwnvX3r+H2MkHoC/QANW2AOuVoZK5qyCH5N8yEAAbWKaQaeL
VBhAYEVKbAkWEtXw7bYXzxRR7WIM3f45v3ncRusDIG+Hf75ZjatoH0lF1gHQNofO
qkCVZVzjkLFuzDic2KZqsNORglNs4J6t5Dahb9v3hnoK963YMnVSUjFvqQ+/RZZy
VILFShilAoGBANucwZU61eJ0tLKBYEwmRY/K7Gu1MvvcYJIOoX8/BL3zNmNO0CLl
NiABtNt9WOVwZxDsxJXdo1zvMtAegNqS6W11R1VAZbL6mQ/krScbLDE6JKA5DmA7
4nNi1gJOW1ziAfdBAfhe4cLbQOb94xkOK5xM1YpO0xgDJLwrZbehDMmPAoGBAMAl
/owPDAvcXz7JFynT0ieYVc64MSFiwGYJcsmxSAnbEgQ+TR5FtkHYe91OSqauZcCd
aoKXQNyrYKIhyounRPFTdYQrlx6KtEs7LU9wOxuphhpJtGjRnhmA7IqvX703wNvu
khrEavn86G5boH8R80371SrN0Rh9UeAlQGuNBdvfAoGAEAmokW9Ug08miwqrr6Pz
3IZjMZJwALidTM1IufQuMnj6ddIhnQrEIx48yPKkdUz6GeBQkuk2rujA+zXfDxc/
eMDhzrX/N0zZtLFse7ieR5IJbrH7/MciyG5lVpHGVkgjAJ18uVikgAhm+vd7iC7i
vG1YAtuyysQgAKXircBTIL0CgYAHeTLWVbt9NpwJwB6DhPaWjalAug9HIiUjktiB
GcEYiQnBWn77X3DATOA8clAa/Yt9m2HKJIHkU1IV3ESZe+8Fh955PozJJlHu3yVb
Ap157PUHTriSnxyMF2Sb3EhX/rQkmbnbCqqygHC14iBy8MrKzLG00X6BelZV5n0D
8d85dwKBgGWY2nsaemPH/TiTVF6kW1IKSQoIyJChkngc+Xj/2aCCkkmAEn8eqncl
RKjnkiEZeG4+G91Xu7+HmcBLwV86k5I+tXK9O1Okomr6Zry8oqVcxU5TB6VRS+rA
ubwF00Drdvk2+kDZfxIM137nBiy7wgCJi2Ksm5ihN3dUF6Q0oNPl
-----END RSA PRIVATE KEY-----`
)

var (
	configDir = filepath.Join(".", "..", "..")
)

type mockFTPClientContext struct {
	lastDataChannel ftpserver.DataChannel
	remoteIP        string
	localIP         string
	extra           any
}

func (cc *mockFTPClientContext) Path() string {
	return ""
}

func (cc *mockFTPClientContext) SetPath(_ string) {}

func (cc *mockFTPClientContext) SetListPath(_ string) {}

func (cc *mockFTPClientContext) SetDebug(_ bool) {}

func (cc *mockFTPClientContext) Debug() bool {
	return false
}

func (cc *mockFTPClientContext) ID() uint32 {
	return 1
}

func (cc *mockFTPClientContext) RemoteAddr() net.Addr {
	ip := "127.0.0.1"
	if cc.remoteIP != "" {
		ip = cc.remoteIP
	}
	return &net.IPAddr{IP: net.ParseIP(ip)}
}

func (cc *mockFTPClientContext) LocalAddr() net.Addr {
	ip := "127.0.0.1"
	if cc.localIP != "" {
		ip = cc.localIP
	}
	return &net.IPAddr{IP: net.ParseIP(ip)}
}

func (cc *mockFTPClientContext) GetClientVersion() string {
	return "mock version"
}

func (cc *mockFTPClientContext) Close() error {
	return nil
}

func (cc *mockFTPClientContext) HasTLSForControl() bool {
	return false
}

func (cc *mockFTPClientContext) HasTLSForTransfers() bool {
	return false
}

func (cc *mockFTPClientContext) SetTLSRequirement(_ ftpserver.TLSRequirement) error {
	return nil
}

func (cc *mockFTPClientContext) GetLastCommand() string {
	return ""
}

func (cc *mockFTPClientContext) GetLastDataChannel() ftpserver.DataChannel {
	return cc.lastDataChannel
}

func (cc *mockFTPClientContext) SetExtra(extra any) {
	cc.extra = extra
}

func (cc *mockFTPClientContext) Extra() any {
	return cc.extra
}

// MockOsFs mockable OsFs
type MockOsFs struct {
	vfs.Fs
	err                     error
	statErr                 error
	isAtomicUploadSupported bool
}

// Name returns the name for the Fs implementation
func (fs MockOsFs) Name() string {
	return "mockOsFs"
}

// IsUploadResumeSupported returns true if resuming uploads is supported
func (MockOsFs) IsUploadResumeSupported() bool {
	return false
}

// IsConditionalUploadResumeSupported returns if resuming uploads is supported
// for the specified size
func (MockOsFs) IsConditionalUploadResumeSupported(_ int64) bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported
func (fs MockOsFs) IsAtomicUploadSupported() bool {
	return fs.isAtomicUploadSupported
}

// Stat returns a FileInfo describing the named file
func (fs MockOsFs) Stat(name string) (os.FileInfo, error) {
	if fs.statErr != nil {
		return nil, fs.statErr
	}
	return os.Stat(name)
}

// Lstat returns a FileInfo describing the named file
func (fs MockOsFs) Lstat(name string) (os.FileInfo, error) {
	if fs.statErr != nil {
		return nil, fs.statErr
	}
	return os.Lstat(name)
}

// Remove removes the named file or (empty) directory.
func (fs MockOsFs) Remove(name string, _ bool) error {
	if fs.err != nil {
		return fs.err
	}
	return os.Remove(name)
}

// Rename renames (moves) source to target
func (fs MockOsFs) Rename(source, target string) (int, int64, error) {
	if fs.err != nil {
		return -1, -1, fs.err
	}
	err := os.Rename(source, target)
	return -1, -1, err
}

func newMockOsFs(err, statErr error, atomicUpload bool, connectionID, rootDir string) vfs.Fs {
	return &MockOsFs{
		Fs:                      vfs.NewOsFs(connectionID, rootDir, "", nil),
		err:                     err,
		statErr:                 statErr,
		isAtomicUploadSupported: atomicUpload,
	}
}

func TestInitialization(t *testing.T) {
	oldMgr := certMgr
	certMgr = nil

	binding := Binding{
		Port: 2121,
	}
	c := &Configuration{
		Bindings:           []Binding{binding},
		CertificateFile:    "acert",
		CertificateKeyFile: "akey",
	}
	assert.False(t, binding.HasProxy())
	assert.Equal(t, util.I18nFTPTLSDisabled, binding.GetTLSDescription())
	err := c.Initialize(configDir)
	assert.Error(t, err)
	c.CertificateFile = ""
	c.CertificateKeyFile = ""
	c.BannerFile = "afile"
	server := NewServer(c, configDir, binding, 0)
	assert.Equal(t, "", server.initialMsg)
	_, err = server.GetTLSConfig()
	assert.Error(t, err)

	binding.TLSMode = 1
	server = NewServer(c, configDir, binding, 0)
	_, err = server.GetSettings()
	assert.Error(t, err)

	binding.PassiveConnectionsSecurity = 100
	binding.ActiveConnectionsSecurity = 100
	server = NewServer(c, configDir, binding, 0)
	_, err = server.GetSettings()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid passive_connections_security")
	}
	binding.PassiveConnectionsSecurity = 1
	server = NewServer(c, configDir, binding, 0)
	_, err = server.GetSettings()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid active_connections_security")
	}
	binding = Binding{
		Port:           2121,
		ForcePassiveIP: "192.168.1",
	}
	server = NewServer(c, configDir, binding, 0)
	_, err = server.GetSettings()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is not valid")
	}

	binding.ForcePassiveIP = "::ffff:192.168.89.9"
	err = binding.checkPassiveIP()
	assert.NoError(t, err)
	assert.Equal(t, "192.168.89.9", binding.ForcePassiveIP)

	binding.ForcePassiveIP = "::1"
	err = binding.checkPassiveIP()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is not a valid IPv4 address")
	}

	err = ReloadCertificateMgr()
	assert.NoError(t, err)

	binding = Binding{
		Port:           2121,
		ClientAuthType: 1,
	}
	assert.Equal(t, util.I18nFTPTLSDisabled, binding.GetTLSDescription())
	certPath := filepath.Join(os.TempDir(), "test_ftpd.crt")
	keyPath := filepath.Join(os.TempDir(), "test_ftpd.key")
	binding.CertificateFile = certPath
	binding.CertificateKeyFile = keyPath
	keyPairs := []common.TLSKeyPair{
		{
			Cert: certPath,
			Key:  keyPath,
			ID:   binding.GetAddress(),
		},
	}
	certMgr, err = common.NewCertManager(keyPairs, configDir, "")
	require.NoError(t, err)

	assert.Equal(t, util.I18nFTPTLSMixed, binding.GetTLSDescription())
	server = NewServer(c, configDir, binding, 0)
	cfg, err := server.GetTLSConfig()
	require.NoError(t, err)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)

	certMgr = oldMgr
}

func TestServerGetSettings(t *testing.T) {
	oldConfig := common.Config
	oldMgr := certMgr

	binding := Binding{
		Port:             2121,
		ApplyProxyConfig: true,
	}
	c := &Configuration{
		Bindings: []Binding{binding},
		PassivePortRange: PortRange{
			Start: 10000,
			End:   11000,
		},
	}
	assert.False(t, binding.HasProxy())
	server := NewServer(c, configDir, binding, 0)
	settings, err := server.GetSettings()
	assert.NoError(t, err)
	assert.Equal(t, 10000, settings.PassiveTransferPortRange.Start)
	assert.Equal(t, 11000, settings.PassiveTransferPortRange.End)

	common.Config.ProxyProtocol = 1
	_, err = server.GetSettings()
	assert.Error(t, err)
	server.binding.Port = 8021

	assert.Equal(t, util.I18nFTPTLSDisabled, binding.GetTLSDescription())
	_, err = server.GetTLSConfig()
	assert.Error(t, err) // TLS configured but cert manager has no certificate

	binding.TLSMode = 1
	assert.Equal(t, util.I18nFTPTLSExplicit, binding.GetTLSDescription())

	binding.TLSMode = 2
	assert.Equal(t, util.I18nFTPTLSImplicit, binding.GetTLSDescription())

	certPath := filepath.Join(os.TempDir(), "test_ftpd.crt")
	keyPath := filepath.Join(os.TempDir(), "test_ftpd.key")
	err = os.WriteFile(certPath, []byte(ftpsCert), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(ftpsKey), os.ModePerm)
	assert.NoError(t, err)

	keyPairs := []common.TLSKeyPair{
		{
			Cert: certPath,
			Key:  keyPath,
			ID:   common.DefaultTLSKeyPaidID,
		},
	}
	certMgr, err = common.NewCertManager(keyPairs, configDir, "")
	require.NoError(t, err)
	common.Config.ProxyAllowed = nil
	c.CertificateFile = certPath
	c.CertificateKeyFile = keyPath
	server = NewServer(c, configDir, binding, 0)
	server.binding.Port = 9021
	settings, err = server.GetSettings()
	assert.NoError(t, err)
	assert.NotNil(t, settings.Listener)

	listener, err := net.Listen("tcp", ":0")
	assert.NoError(t, err)
	listener, err = server.WrapPassiveListener(listener)
	assert.NoError(t, err)

	_, ok := listener.(*proxyproto.Listener)
	assert.True(t, ok)

	common.Config = oldConfig
	certMgr = oldMgr
}

func TestUserInvalidParams(t *testing.T) {
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: "invalid",
		},
	}
	binding := Binding{
		Port: 2121,
	}
	c := &Configuration{
		Bindings: []Binding{binding},
		PassivePortRange: PortRange{
			Start: 10000,
			End:   11000,
		},
	}
	server := NewServer(c, configDir, binding, 3)
	_, err := server.validateUser(u, &mockFTPClientContext{}, dataprovider.LoginMethodPassword)
	assert.Error(t, err)

	u.Username = "a"
	u.HomeDir = filepath.Clean(os.TempDir())
	subDir := "subdir"
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir1", subDir)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
	})
	_, err = server.validateUser(u, &mockFTPClientContext{}, dataprovider.LoginMethodPassword)
	assert.Error(t, err)
	u.VirtualFolders = nil
	_, err = server.validateUser(u, &mockFTPClientContext{}, dataprovider.LoginMethodPassword)
	assert.Error(t, err)
}

func TestFTPMode(t *testing.T) {
	connection := &Connection{
		BaseConnection: common.NewBaseConnection("", common.ProtocolFTP, "", "", dataprovider.User{}),
	}
	assert.Empty(t, connection.getFTPMode())
	connection.clientContext = &mockFTPClientContext{lastDataChannel: ftpserver.DataChannelActive}
	assert.Equal(t, "active", connection.getFTPMode())
	connection.clientContext = &mockFTPClientContext{lastDataChannel: ftpserver.DataChannelPassive}
	assert.Equal(t, "passive", connection.getFTPMode())
	connection.clientContext = &mockFTPClientContext{lastDataChannel: 0}
	assert.Empty(t, connection.getFTPMode())
}

func TestClientVersion(t *testing.T) {
	mockCC := &mockFTPClientContext{}
	connID := fmt.Sprintf("2_%v", mockCC.ID())
	user := dataprovider.User{}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, "", "", user),
		clientContext:  mockCC,
	}
	err := common.Connections.Add(connection)
	assert.NoError(t, err)
	stats := common.Connections.GetStats("")
	if assert.Len(t, stats, 1) {
		assert.Equal(t, "mock version", stats[0].ClientVersion)
		common.Connections.Remove(connection.GetID())
	}
	assert.Len(t, common.Connections.GetStats(""), 0)
}

func TestDriverMethodsNotImplemented(t *testing.T) {
	mockCC := &mockFTPClientContext{}
	connID := fmt.Sprintf("2_%v", mockCC.ID())
	user := dataprovider.User{}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, "", "", user),
		clientContext:  mockCC,
	}
	_, err := connection.Create("")
	assert.EqualError(t, err, errNotImplemented.Error())
	err = connection.MkdirAll("", os.ModePerm)
	assert.EqualError(t, err, errNotImplemented.Error())
	_, err = connection.Open("")
	assert.EqualError(t, err, errNotImplemented.Error())
	_, err = connection.OpenFile("", 0, os.ModePerm)
	assert.EqualError(t, err, errNotImplemented.Error())
	err = connection.RemoveAll("")
	assert.EqualError(t, err, errNotImplemented.Error())
	assert.Equal(t, connection.GetID(), connection.Name())
}

func TestExtraData(t *testing.T) {
	mockCC := mockFTPClientContext{}
	_, ok := mockCC.Extra().(bool)
	require.False(t, ok)
	mockCC.SetExtra(false)
	val, ok := mockCC.Extra().(bool)
	require.True(t, ok)
	require.False(t, val)
	mockCC.SetExtra(true)
	val, ok = mockCC.Extra().(bool)
	require.True(t, ok)
	require.True(t, val)
}

func TestResolvePathErrors(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: "invalid",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	mockCC := &mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, "", "", user),
		clientContext:  mockCC,
	}
	err := connection.Mkdir("", os.ModePerm)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.Remove("")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.RemoveDir("")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.Rename("", "")
	assert.ErrorIs(t, err, common.ErrOpUnsupported)
	err = connection.Symlink("", "")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	_, err = connection.Stat("")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.Chmod("", os.ModePerm)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	err = connection.Chtimes("", time.Now(), time.Now())
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	_, err = connection.ReadDir("")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	_, err = connection.GetHandle("", 0, 0)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
	_, err = connection.GetAvailableSpace("")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrGenericFailure.Error())
	}
}

func TestUploadFileStatError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test is not available on Windows")
	}
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "user",
			HomeDir:  filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	mockCC := &mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	fs := vfs.NewOsFs(connID, user.HomeDir, "", nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, "", "", user),
		clientContext:  mockCC,
	}
	testFile := filepath.Join(user.HomeDir, "test", "testfile")
	err := os.MkdirAll(filepath.Dir(testFile), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(testFile, []byte("data"), os.ModePerm)
	assert.NoError(t, err)
	err = os.Chmod(filepath.Dir(testFile), 0001)
	assert.NoError(t, err)
	_, err = connection.uploadFile(fs, testFile, "test", 0)
	assert.Error(t, err)
	err = os.Chmod(filepath.Dir(testFile), os.ModePerm)
	assert.NoError(t, err)
	err = os.RemoveAll(filepath.Dir(testFile))
	assert.NoError(t, err)
}

func TestAVBLErrors(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "user",
			HomeDir:  filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	mockCC := &mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, "", "", user),
		clientContext:  mockCC,
	}
	_, err := connection.GetAvailableSpace("/")
	assert.NoError(t, err)
	_, err = connection.GetAvailableSpace("/missing-path")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, fs.ErrNotExist))
}

func TestUploadOverwriteErrors(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "user",
			HomeDir:  filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	mockCC := &mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	fs := newMockOsFs(nil, nil, false, connID, user.GetHomeDir())
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, "", "", user),
		clientContext:  mockCC,
	}
	flags := 0
	flags |= os.O_APPEND
	_, err := connection.handleFTPUploadToExistingFile(fs, flags, "", "", 0, "")
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrOpUnsupported.Error())
	}

	f, err := os.CreateTemp("", "temp")
	assert.NoError(t, err)
	err = f.Close()
	assert.NoError(t, err)
	flags = 0
	flags |= os.O_CREATE
	flags |= os.O_TRUNC
	tr, err := connection.handleFTPUploadToExistingFile(fs, flags, f.Name(), f.Name(), 123, f.Name())
	if assert.NoError(t, err) {
		transfer := tr.(*transfer)
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

	_, err = connection.handleFTPUploadToExistingFile(fs, os.O_TRUNC, filepath.Join(os.TempDir(), "sub", "file"),
		filepath.Join(os.TempDir(), "sub", "file1"), 0, "/sub/file1")
	assert.Error(t, err)
	fs = vfs.NewOsFs(connID, user.GetHomeDir(), "", nil)
	_, err = connection.handleFTPUploadToExistingFile(fs, 0, "missing1", "missing2", 0, "missing")
	assert.Error(t, err)
}

func TestTransferErrors(t *testing.T) {
	testfile := "testfile"
	file, err := os.Create(testfile)
	assert.NoError(t, err)
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "user",
			HomeDir:  filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	mockCC := &mockFTPClientContext{}
	connID := fmt.Sprintf("%v", mockCC.ID())
	fs := newMockOsFs(nil, nil, false, connID, user.GetHomeDir())
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(connID, common.ProtocolFTP, "", "", user),
		clientContext:  mockCC,
	}
	baseTransfer := common.NewBaseTransfer(file, connection.BaseConnection, nil, file.Name(), file.Name(), testfile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	tr := newTransfer(baseTransfer, nil, nil, 0)
	err = tr.Close()
	assert.NoError(t, err)
	_, err = tr.Seek(10, 0)
	assert.Error(t, err)
	buf := make([]byte, 64)
	_, err = tr.Read(buf)
	assert.Error(t, err)
	err = tr.Close()
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrTransferClosed.Error())
	}
	assert.Len(t, connection.GetTransfers(), 0)

	r, _, err := pipeat.Pipe()
	assert.NoError(t, err)
	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testfile, testfile, testfile,
		common.TransferUpload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	tr = newTransfer(baseTransfer, nil, vfs.NewPipeReader(r), 10)
	pos, err := tr.Seek(10, 0)
	assert.NoError(t, err)
	assert.Equal(t, pos, tr.expectedOffset)
	err = tr.closeIO()
	assert.NoError(t, err)

	r, w, err := pipeat.Pipe()
	assert.NoError(t, err)
	pipeWriter := vfs.NewPipeWriter(w)
	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testfile, testfile, testfile,
		common.TransferUpload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	tr = newTransfer(baseTransfer, pipeWriter, nil, 0)

	err = r.Close()
	assert.NoError(t, err)
	errFake := fmt.Errorf("fake upload error")
	go func() {
		time.Sleep(100 * time.Millisecond)
		pipeWriter.Done(errFake)
	}()
	err = tr.closeIO()
	assert.EqualError(t, err, errFake.Error())
	_, err = tr.Seek(1, 0)
	if assert.Error(t, err) {
		assert.EqualError(t, err, common.ErrOpUnsupported.Error())
	}
	err = os.Remove(testfile)
	assert.NoError(t, err)
}

func TestVerifyTLSConnection(t *testing.T) {
	oldCertMgr := certMgr

	caCrlPath := filepath.Join(os.TempDir(), "testcrl.crt")
	certPath := filepath.Join(os.TempDir(), "test.crt")
	keyPath := filepath.Join(os.TempDir(), "test.key")
	err := os.WriteFile(caCrlPath, []byte(caCRL), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(certPath, []byte(ftpsCert), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(ftpsKey), os.ModePerm)
	assert.NoError(t, err)
	keyPairs := []common.TLSKeyPair{
		{
			Cert: certPath,
			Key:  keyPath,
			ID:   common.DefaultTLSKeyPaidID,
		},
	}
	certMgr, err = common.NewCertManager(keyPairs, "", "ftp_test")
	assert.NoError(t, err)

	certMgr.SetCARevocationLists([]string{caCrlPath})
	err = certMgr.LoadCRLs()
	assert.NoError(t, err)

	crt, err := tls.X509KeyPair([]byte(client1Crt), []byte(client1Key))
	assert.NoError(t, err)
	x509crt, err := x509.ParseCertificate(crt.Certificate[0])
	assert.NoError(t, err)

	server := Server{}
	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{x509crt},
	}

	err = server.verifyTLSConnection(state)
	assert.Error(t, err) // no verified certification chain
	err = server.VerifyTLSConnectionState(nil, state)
	assert.NoError(t, err)
	server.binding.ClientAuthType = 1
	err = server.VerifyTLSConnectionState(nil, state)
	assert.Error(t, err)

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

func TestCiphers(t *testing.T) {
	b := Binding{
		TLSCipherSuites: []string{},
	}
	b.setCiphers()
	require.Equal(t, util.GetTLSCiphersFromNames(nil), b.ciphers)
	b.TLSCipherSuites = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}
	b.setCiphers()
	require.Len(t, b.ciphers, 2)
	require.Equal(t, []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384}, b.ciphers)
}

func TestPassiveIPResolver(t *testing.T) {
	b := Binding{
		PassiveIPOverrides: []PassiveIPOverride{
			{},
		},
	}
	err := b.checkPassiveIP()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "passive IP networks override cannot be empty")
	b = Binding{
		PassiveIPOverrides: []PassiveIPOverride{
			{
				IP: "invalid ip",
			},
		},
	}
	err = b.checkPassiveIP()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is not valid")

	b = Binding{
		PassiveIPOverrides: []PassiveIPOverride{
			{
				IP:       "192.168.1.1",
				Networks: []string{"192.168.1.0/24", "invalid cidr"},
			},
		},
	}
	err = b.checkPassiveIP()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid passive IP networks override")
	b = Binding{
		ForcePassiveIP: "192.168.2.1",
		PassiveIPOverrides: []PassiveIPOverride{
			{
				IP:       "::ffff:192.168.1.1",
				Networks: []string{"192.168.1.0/24"},
			},
		},
	}
	err = b.checkPassiveIP()
	assert.NoError(t, err)
	assert.NotEmpty(t, b.PassiveIPOverrides[0].GetNetworksAsString())
	assert.Equal(t, "192.168.1.1", b.PassiveIPOverrides[0].IP)
	require.Len(t, b.PassiveIPOverrides[0].parsedNetworks, 1)
	ip := net.ParseIP("192.168.1.2")
	assert.True(t, b.PassiveIPOverrides[0].parsedNetworks[0](ip))
	ip = net.ParseIP("192.168.0.2")
	assert.False(t, b.PassiveIPOverrides[0].parsedNetworks[0](ip))

	mockCC := &mockFTPClientContext{
		remoteIP: "192.168.1.10",
		localIP:  "192.168.1.3",
	}
	passiveIP, err := b.passiveIPResolver(mockCC)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", passiveIP)
	b.PassiveIPOverrides[0].IP = ""
	passiveIP, err = b.passiveIPResolver(mockCC)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.3", passiveIP)
	mockCC.remoteIP = "172.16.2.3"
	passiveIP, err = b.passiveIPResolver(mockCC)
	assert.NoError(t, err)
	assert.Equal(t, b.ForcePassiveIP, passiveIP)
}

func TestRelativePath(t *testing.T) {
	rel := getPathRelativeTo("/testpath", "/testpath")
	assert.Empty(t, rel)
	rel = getPathRelativeTo("/", "/")
	assert.Empty(t, rel)
	rel = getPathRelativeTo("/", "/dir/sub")
	assert.Equal(t, "dir/sub", rel)
	rel = getPathRelativeTo("./", "/dir/sub")
	assert.Equal(t, "/dir/sub", rel)
	rel = getPathRelativeTo("/sub", "/dir/sub")
	assert.Equal(t, "../dir/sub", rel)
	rel = getPathRelativeTo("/dir", "/dir/sub")
	assert.Equal(t, "sub", rel)
	rel = getPathRelativeTo("/dir/sub", "/dir")
	assert.Equal(t, "../", rel)
	rel = getPathRelativeTo("dir", "/dir1")
	assert.Equal(t, "/dir1", rel)
	rel = getPathRelativeTo("", "/dir2")
	assert.Equal(t, "dir2", rel)
	rel = getPathRelativeTo(".", "/dir2")
	assert.Equal(t, "/dir2", rel)
	rel = getPathRelativeTo("/dir3", "dir3")
	assert.Equal(t, "dir3", rel)
}

func TestConfigsFromProvider(t *testing.T) {
	err := dataprovider.UpdateConfigs(nil, "", "", "")
	assert.NoError(t, err)
	c := Configuration{}
	err = c.loadFromProvider()
	assert.NoError(t, err)
	assert.Empty(t, c.acmeDomain)
	configs := dataprovider.Configs{
		ACME: &dataprovider.ACMEConfigs{
			Domain:          "domain.com",
			Email:           "info@domain.com",
			HTTP01Challenge: dataprovider.ACMEHTTP01Challenge{Port: 80},
			Protocols:       2,
		},
	}
	err = dataprovider.UpdateConfigs(&configs, "", "", "")
	assert.NoError(t, err)
	util.CertsBasePath = ""
	// crt and key empty
	err = c.loadFromProvider()
	assert.NoError(t, err)
	assert.Empty(t, c.acmeDomain)
	util.CertsBasePath = filepath.Clean(os.TempDir())
	// crt not found
	err = c.loadFromProvider()
	assert.NoError(t, err)
	assert.Empty(t, c.acmeDomain)
	keyPairs := c.getKeyPairs(configDir)
	assert.Len(t, keyPairs, 0)
	crtPath := filepath.Join(util.CertsBasePath, util.SanitizeDomain(configs.ACME.Domain)+".crt")
	err = os.WriteFile(crtPath, nil, 0666)
	assert.NoError(t, err)
	// key not found
	err = c.loadFromProvider()
	assert.NoError(t, err)
	assert.Empty(t, c.acmeDomain)
	keyPairs = c.getKeyPairs(configDir)
	assert.Len(t, keyPairs, 0)
	keyPath := filepath.Join(util.CertsBasePath, util.SanitizeDomain(configs.ACME.Domain)+".key")
	err = os.WriteFile(keyPath, nil, 0666)
	assert.NoError(t, err)
	// acme cert used
	err = c.loadFromProvider()
	assert.NoError(t, err)
	assert.Equal(t, configs.ACME.Domain, c.acmeDomain)
	keyPairs = c.getKeyPairs(configDir)
	assert.Len(t, keyPairs, 1)
	// protocols does not match
	configs.ACME.Protocols = 5
	err = dataprovider.UpdateConfigs(&configs, "", "", "")
	assert.NoError(t, err)
	c.acmeDomain = ""
	err = c.loadFromProvider()
	assert.NoError(t, err)
	assert.Empty(t, c.acmeDomain)
	keyPairs = c.getKeyPairs(configDir)
	assert.Len(t, keyPairs, 0)

	err = os.Remove(crtPath)
	assert.NoError(t, err)
	err = os.Remove(keyPath)
	assert.NoError(t, err)
	util.CertsBasePath = ""
	err = dataprovider.UpdateConfigs(nil, "", "", "")
	assert.NoError(t, err)
}

func TestPassiveHost(t *testing.T) {
	b := Binding{
		PassiveHost: "invalid hostname",
	}
	_, err := b.getPassiveIP(nil)
	assert.Error(t, err)
	b.PassiveHost = "localhost"
	ip, err := b.getPassiveIP(nil)
	assert.NoError(t, err, ip)
	assert.Equal(t, "127.0.0.1", ip)
}
