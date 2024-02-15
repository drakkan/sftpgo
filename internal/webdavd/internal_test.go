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

package webdavd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
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

	"github.com/drakkan/webdav"
	"github.com/eikenb/pipeat"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
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
func (fs *MockOsFs) Open(name string, offset int64) (vfs.File, vfs.PipeReader, func(), error) {
	if fs.reader != nil {
		return nil, vfs.NewPipeReader(fs.reader), nil, nil
	}
	return fs.Fs.Open(name, offset)
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
func (fs *MockOsFs) Remove(name string, _ bool) error {
	if fs.err != nil {
		return fs.err
	}
	return os.Remove(name)
}

// Rename renames (moves) source to target
func (fs *MockOsFs) Rename(source, target string) (int, int64, error) {
	err := os.Rename(source, target)
	return -1, -1, err
}

// GetMimeType returns the content type
func (fs *MockOsFs) GetMimeType(_ string) (string, error) {
	if fs.err != nil {
		return "", fs.err
	}
	return "application/custom-mime", nil
}

func newMockOsFs(atomicUpload bool, connectionID, rootDir string, reader *pipeat.PipeReaderAt, err error) vfs.Fs {
	return &MockOsFs{
		Fs:                      vfs.NewOsFs(connectionID, rootDir, "", nil),
		isAtomicUploadSupported: atomicUpload,
		reader:                  reader,
		err:                     err,
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
		assert.EqualError(t, err, fmt.Sprintf("cannot login user with invalid home dir: %q", u.HomeDir))
	}

	req.TLS = &tls.ConnectionState{}
	writeLog(req, http.StatusOK, nil)
}

func TestAllowedProxyUnixDomainSocket(t *testing.T) {
	b := Binding{
		Address:      filepath.Join(os.TempDir(), "sock"),
		ProxyAllowed: []string{"127.0.0.1", "127.0.1.1"},
	}
	err := b.parseAllowedProxy()
	assert.NoError(t, err)
	if assert.Len(t, b.allowHeadersFrom, 1) {
		assert.True(t, b.allowHeadersFrom[0](nil))
	}
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

	trueClientIP := "True-Client-IP"
	cfConnectingIP := "CF-Connecting-IP"
	xff := "X-Forwarded-For"
	xRealIP := "X-Real-IP"

	req.Header.Set(trueClientIP, remoteAddr1)
	ip := util.GetRealIP(req, trueClientIP, 0)
	assert.Equal(t, remoteAddr1, ip)
	ip = util.GetRealIP(req, trueClientIP, 2)
	assert.Empty(t, ip)
	req.Header.Del(trueClientIP)
	req.Header.Set(cfConnectingIP, remoteAddr1)
	ip = util.GetRealIP(req, cfConnectingIP, 0)
	assert.Equal(t, remoteAddr1, ip)
	req.Header.Del(cfConnectingIP)
	req.Header.Set(xff, remoteAddr1)
	ip = util.GetRealIP(req, xff, 0)
	assert.Equal(t, remoteAddr1, ip)
	// this will be ignored, remoteAddr1 is not allowed to se this header
	req.Header.Set(xff, remoteAddr2)
	req.RemoteAddr = remoteAddr1
	ip = server.checkRemoteAddress(req)
	assert.Equal(t, remoteAddr1, ip)
	req.RemoteAddr = ""
	ip = server.checkRemoteAddress(req)
	assert.Empty(t, ip)

	req.Header.Set(xff, fmt.Sprintf("%v , %v", remoteAddr2, remoteAddr1))
	ip = util.GetRealIP(req, xff, 1)
	assert.Equal(t, remoteAddr2, ip)

	req.RemoteAddr = remoteAddr2
	req.Header.Set(xff, fmt.Sprintf("%v,%v", "12.34.56.78", "172.16.2.4"))
	server.binding.ClientIPHeaderDepth = 1
	server.binding.ClientIPProxyHeader = xff
	ip = server.checkRemoteAddress(req)
	assert.Equal(t, "12.34.56.78", ip)
	assert.Equal(t, ip, req.RemoteAddr)

	req.RemoteAddr = remoteAddr2
	req.Header.Set(xff, fmt.Sprintf("%v,%v", "12.34.56.79", "172.16.2.5"))
	server.binding.ClientIPHeaderDepth = 0
	ip = server.checkRemoteAddress(req)
	assert.Equal(t, "172.16.2.5", ip)
	assert.Equal(t, ip, req.RemoteAddr)

	req.RemoteAddr = "10.8.0.2"
	req.Header.Set(xff, remoteAddr1)
	ip = server.checkRemoteAddress(req)
	assert.Equal(t, remoteAddr1, ip)
	assert.Equal(t, ip, req.RemoteAddr)

	req.RemoteAddr = "10.8.0.3"
	req.Header.Set(xff, "not an ip")
	ip = server.checkRemoteAddress(req)
	assert.Equal(t, "10.8.0.3", ip)
	assert.Equal(t, ip, req.RemoteAddr)

	req.Header.Del(xff)
	req.RemoteAddr = ""
	req.Header.Set(xRealIP, remoteAddr1)
	ip = util.GetRealIP(req, "x-real-ip", 0)
	assert.Equal(t, remoteAddr1, ip)
	req.RemoteAddr = ""
}

func TestConnWithNilRequest(t *testing.T) {
	c := &Connection{}
	assert.Empty(t, c.GetClientVersion())
	assert.Empty(t, c.GetCommand())
	assert.Empty(t, c.GetRemoteAddress())
	assert.True(t, c.getModificationTime().IsZero())
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
	fs := vfs.NewOsFs("connID", user.HomeDir, "", nil)
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
		fs := vfs.NewOsFs("connID", connection.User.HomeDir, "", nil)
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
	fs := vfs.NewOsFs("connID", user.HomeDir, "", nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}
	missingPath := "missing path"
	fsMissingPath := filepath.Join(user.HomeDir, missingPath)
	err := connection.RemoveAll(ctx, missingPath)
	assert.ErrorIs(t, err, os.ErrNotExist)
	davFile, err := connection.getFile(fs, fsMissingPath, missingPath)
	assert.NoError(t, err)
	buf := make([]byte, 64)
	_, err = davFile.Read(buf)
	assert.ErrorIs(t, err, os.ErrNotExist)
	err = davFile.Close()
	assert.ErrorIs(t, err, os.ErrNotExist)
	p := filepath.Join(user.HomeDir, "adir", missingPath)
	_, err = connection.handleUploadToNewFile(fs, p, p, path.Join("adir", missingPath))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = connection.handleUploadToExistingFile(fs, p, "_"+p, 0, path.Join("adir", missingPath))
	if assert.Error(t, err) {
		assert.ErrorIs(t, err, os.ErrNotExist)
	}

	fs = newMockOsFs(false, fs.ConnectionID(), user.HomeDir, nil, nil)
	_, err = connection.handleUploadToExistingFile(fs, p, p, 0, path.Join("adir", missingPath))
	assert.ErrorIs(t, err, os.ErrNotExist)

	f, err := os.CreateTemp("", "temp")
	assert.NoError(t, err)
	err = f.Close()
	assert.NoError(t, err)
	davFile, err = connection.handleUploadToExistingFile(fs, f.Name(), f.Name(), 123, f.Name())
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
		// test PROPPATCH date parsing error
		pstats, err := transfer.Patch([]webdav.Proppatch{
			{
				Props: []webdav.Property{
					{
						XMLName: xml.Name{
							Space: "DAV",
							Local: "getlastmodified",
						},
						InnerXML: []byte(`Wid, 04 Nov 2020 13:25:51 GMT`),
					},
				},
			},
		})
		assert.NoError(t, err)
		for _, pstat := range pstats {
			assert.Equal(t, http.StatusForbidden, pstat.Status)
		}

		err = os.Remove(f.Name())
		assert.NoError(t, err)
		// the file is deleted PROPPATCH should fail
		pstats, err = transfer.Patch([]webdav.Proppatch{
			{
				Props: []webdav.Property{
					{
						XMLName: xml.Name{
							Space: "DAV",
							Local: "getlastmodified",
						},
						InnerXML: []byte(`Wed, 04 Nov 2020 13:25:51 GMT`),
					},
				},
			},
		})
		assert.NoError(t, err)
		for _, pstat := range pstats {
			assert.Equal(t, http.StatusForbidden, pstat.Status)
		}
	}
}

func TestCheckRequestMethodWithPrefix(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: filepath.Clean(os.TempDir()),
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
	}
	fs := vfs.NewOsFs("connID", user.HomeDir, "", nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}
	server := webDavServer{
		binding: Binding{
			Prefix: "/dav",
		},
	}
	req, err := http.NewRequest(http.MethodGet, "/../dav", nil)
	require.NoError(t, err)
	server.checkRequestMethod(context.Background(), req, connection)
	require.Equal(t, "PROPFIND", req.Method)
	require.Equal(t, "1", req.Header.Get("Depth"))
}

func TestContentType(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("connID", user.HomeDir, "", nil)
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}
	testFilePath := filepath.Join(user.HomeDir, testFile)
	ctx := context.Background()
	baseTransfer := common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile+".unknown",
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	fs = newMockOsFs(false, fs.ConnectionID(), user.GetHomeDir(), nil, nil)
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
	assert.ErrorIs(t, err, webdav.ErrNotImplemented)
	_, err = davFile.ReadDir()
	assert.Error(t, err)
	err = davFile.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile+".unknown1",
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = vfs.NewOsFs("id", user.HomeDir, "", nil)
	fi, err = davFile.Stat()
	if assert.NoError(t, err) {
		ctype, err := fi.(*webDavFileInfo).ContentType(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/plain; charset=utf-8", ctype)
	}
	err = davFile.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = vfs.NewOsFs("id", user.HomeDir, "", nil)
	fi, err = davFile.Stat()
	if assert.NoError(t, err) {
		ctype, err := fi.(*webDavFileInfo).ContentType(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "application/octet-stream", ctype)
	}
	err = davFile.Close()
	assert.NoError(t, err)

	for i := 0; i < 2; i++ {
		// the second time the cache will be used
		baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile+".custom",
			common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
		davFile = newWebDavFile(baseTransfer, nil, nil)
		davFile.Fs = vfs.NewOsFs("id", user.HomeDir, "", nil)
		fi, err = davFile.Stat()
		if assert.NoError(t, err) {
			ctype, err := fi.(*webDavFileInfo).ContentType(ctx)
			assert.NoError(t, err)
			assert.Equal(t, "text/plain; charset=utf-8", ctype)
		}
		err = davFile.Close()
		assert.NoError(t, err)
	}

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile+".sftpgo",
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	fs = newMockOsFs(false, fs.ConnectionID(), user.GetHomeDir(), nil, os.ErrInvalid)
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = fs
	fi, err = davFile.Stat()
	if assert.NoError(t, err) {
		ctype, err := fi.(*webDavFileInfo).ContentType(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "application/sftpgo", ctype)
	}

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile+".unknown2",
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	fs = newMockOsFs(false, fs.ConnectionID(), user.GetHomeDir(), nil, os.ErrInvalid)
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = fs
	fi, err = davFile.Stat()
	if assert.NoError(t, err) {
		ctype, err := fi.(*webDavFileInfo).ContentType(ctx)
		assert.EqualError(t, err, webdav.ErrNotImplemented.Error(), "unexpected content type %q", ctype)
	}
	cache := mimeCache{
		maxSize:   10,
		mimeTypes: map[string]string{},
	}
	cache.addMimeToCache("", "")
	cache.RLock()
	assert.Len(t, cache.mimeTypes, 0)
	cache.RUnlock()

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
	fs := vfs.NewOsFs("connID", user.HomeDir, "", nil)
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
	assert.True(t, fs.IsNotExist(err))
	_, err = davFile.Stat()
	assert.True(t, fs.IsNotExist(err))

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
	mockFs := newMockOsFs(false, fs.ConnectionID(), user.HomeDir, r, nil)
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
	fs := newMockOsFs(true, "connID", user.HomeDir, nil, nil)
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
	assert.True(t, fs.IsNotExist(err))
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
	err = davFile.Close()
	assert.NoError(t, err)
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	davFile = newWebDavFile(baseTransfer, nil, nil)
	res, err = davFile.Seek(0, io.SeekEnd)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(testFileContents)), res)
	err = davFile.updateStatInfo()
	assert.NoError(t, err)
	err = davFile.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath+"1", testFilePath+"1", testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	_, err = davFile.Seek(0, io.SeekEnd)
	assert.True(t, fs.IsNotExist(err))
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	fs = vfs.NewOsFs(fs.ConnectionID(), user.GetHomeDir(), "", nil)
	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath+"1", testFilePath+"1", testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	_, err = davFile.Seek(0, io.SeekEnd)
	assert.True(t, fs.IsNotExist(err))
	davFile.Connection.RemoveTransfer(davFile.BaseTransfer)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.reader = f
	r, _, err := pipeat.Pipe()
	assert.NoError(t, err)
	davFile.Fs = newMockOsFs(true, fs.ConnectionID(), user.GetHomeDir(), r, nil)
	res, err = davFile.Seek(2, io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), res)
	err = davFile.Close()
	assert.NoError(t, err)

	r, _, err = pipeat.Pipe()
	assert.NoError(t, err)
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = newMockOsFs(true, fs.ConnectionID(), user.GetHomeDir(), r, nil)
	res, err = davFile.Seek(2, io.SeekEnd)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), res)
	err = davFile.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath+"1", testFilePath+"1", testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{AllowedTotalSize: 100})

	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = newMockOsFs(true, fs.ConnectionID(), user.GetHomeDir(), nil, nil)
	res, err = davFile.Seek(2, io.SeekEnd)
	assert.True(t, fs.IsNotExist(err))
	assert.Equal(t, int64(0), res)

	assert.Len(t, common.Connections.GetStats(""), 0)

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
	err := dataprovider.AddUser(&u, "", "", "")
	assert.NoError(t, err)
	user, err := dataprovider.UserExists(u.Username, "")
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
	err = dataprovider.UpdateUser(&user, "", "", "")
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.True(t, ok)
	folderName := "testFolder"
	f := &vfs.BaseVirtualFolder{
		Name:       folderName,
		MappedPath: filepath.Join(os.TempDir(), "mapped"),
	}
	err = dataprovider.AddFolder(f, "", "", "")
	assert.NoError(t, err)
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderName,
		},
		VirtualPath: "/vdir",
	})

	err = dataprovider.UpdateUser(&user, "", "", "")
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
	err = dataprovider.DeleteUser(user.Username, "", "", "")
	assert.NoError(t, err)
	_, ok = dataprovider.GetCachedWebDAVUser(username)
	assert.False(t, ok)

	err = dataprovider.DeleteFolder(folderName, "", "", "")
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
			Name: folderName,
		},
		VirtualPath: "/vpath",
	})
	f := &vfs.BaseVirtualFolder{
		Name:       folderName,
		MappedPath: filepath.Join(os.TempDir(), folderName),
	}
	err := dataprovider.AddFolder(f, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.AddUser(&u, "", "", "")
	assert.NoError(t, err)
	user, err := dataprovider.UserExists(u.Username, "")
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
	err = dataprovider.UpdateFolder(&folder, folder.Users, folder.Groups, "", "", "")
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
	err = dataprovider.UpdateFolder(&folder, folder.Users, folder.Groups, "", "", "")
	assert.NoError(t, err)
	_, isCached, _, loginMethod, err = server.authenticate(req, ipAddr)
	assert.NoError(t, err)
	assert.False(t, isCached)
	assert.Equal(t, dataprovider.LoginMethodPassword, loginMethod)
	cachedUser, ok = dataprovider.GetCachedWebDAVUser(username)
	if assert.True(t, ok) {
		assert.False(t, cachedUser.IsExpired())
	}

	err = dataprovider.DeleteFolder(folderName, "", "", "")
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

	err = dataprovider.DeleteUser(user.Username, "", "", "")
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
	err := dataprovider.AddUser(&u, "", "", "")
	assert.NoError(t, err)
	user1, err := dataprovider.UserExists(u.Username, "")
	assert.NoError(t, err)
	u.Username = username + "2"
	u.Password = password + "2"
	err = dataprovider.AddUser(&u, "", "", "")
	assert.NoError(t, err)
	user2, err := dataprovider.UserExists(u.Username, "")
	assert.NoError(t, err)
	u.Username = username + "3"
	u.Password = password + "3"
	err = dataprovider.AddUser(&u, "", "", "")
	assert.NoError(t, err)
	user3, err := dataprovider.UserExists(u.Username, "")
	assert.NoError(t, err)
	u.Username = username + "4"
	u.Password = password + "4"
	err = dataprovider.AddUser(&u, "", "", "")
	assert.NoError(t, err)
	user4, err := dataprovider.UserExists(u.Username, "")
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
	err = dataprovider.UpdateUser(&user1, "", "", "")
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

	err = dataprovider.DeleteUser(user1.Username, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(user2.Username, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(user3.Username, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(user4.Username, "", "", "")
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
	err := dataprovider.AddUser(&u, "", "", "")
	assert.NoError(t, err)
	user, err := dataprovider.UserExists(u.Username, "")
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

	err = dataprovider.DeleteUser(username, "", "", "")
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

	keyPairs := []common.TLSKeyPair{
		{
			Cert: certPath,
			Key:  keyPath,
			ID:   common.DefaultTLSKeyPaidID,
		},
	}
	certMgr, err = common.NewCertManager(keyPairs, "", "webdav_test")
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

func TestParseTime(t *testing.T) {
	res, err := parseTime("Sat, 4 Feb 2023 17:00:50 GMT")
	require.NoError(t, err)
	require.Equal(t, int64(1675530050), res.Unix())
	res, err = parseTime("Wed, 04 Nov 2020 13:25:51 GMT")
	require.NoError(t, err)
	require.Equal(t, int64(1604496351), res.Unix())
}

func TestConfigsFromProvider(t *testing.T) {
	configDir := "."
	err := dataprovider.UpdateConfigs(nil, "", "", "")
	assert.NoError(t, err)
	c := Configuration{
		Bindings: []Binding{
			{
				Port: 1234,
			},
		},
	}
	err = c.loadFromProvider()
	assert.NoError(t, err)
	assert.Empty(t, c.acmeDomain)
	configs := dataprovider.Configs{
		ACME: &dataprovider.ACMEConfigs{
			Domain:          "domain.com",
			Email:           "info@domain.com",
			HTTP01Challenge: dataprovider.ACMEHTTP01Challenge{Port: 80},
			Protocols:       7,
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
	assert.True(t, c.Bindings[0].EnableHTTPS)
	// protocols does not match
	configs.ACME.Protocols = 3
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

func TestGetCacheExpirationTime(t *testing.T) {
	c := UsersCacheConfig{}
	assert.True(t, c.getExpirationTime().IsZero())
	c.ExpirationTime = 1
	assert.False(t, c.getExpirationTime().IsZero())
}
