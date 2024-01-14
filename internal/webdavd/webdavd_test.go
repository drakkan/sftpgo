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

package webdavd_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/sio"
	"github.com/rs/zerolog"
	"github.com/sftpgo/sdk"
	sdkkms "github.com/sftpgo/sdk/kms"
	"github.com/stretchr/testify/assert"
	"github.com/studio-b12/gowebdav"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpclient"
	"github.com/drakkan/sftpgo/v2/internal/httpdtest"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/drakkan/sftpgo/v2/internal/webdavd"
)

const (
	logSender           = "webavdTesting"
	webDavServerAddr    = "localhost:9090"
	webDavTLSServerAddr = "localhost:9443"
	webDavServerPort    = 9090
	webDavTLSServerPort = 9443
	sftpServerAddr      = "127.0.0.1:9022"
	defaultUsername     = "test_user_dav"
	defaultPassword     = "test_password"
	osWindows           = "windows"
	webDavCert          = `-----BEGIN CERTIFICATE-----
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
	testFileName        = "test_file_dav.dat"
	testDLFileName      = "test_download_dav.dat"
	tlsClient1Username  = "client1"
	tlsClient2Username  = "client2"
	emptyPwdPlaceholder = "empty"
	ocMtimeHeader       = "X-OC-Mtime"
)

var (
	configDir       = filepath.Join(".", "..", "..")
	allPerms        = []string{dataprovider.PermAny}
	homeBasePath    string
	hookCmdPath     string
	extAuthPath     string
	preLoginPath    string
	postConnectPath string
	preDownloadPath string
	preUploadPath   string
	logFilePath     string
	certPath        string
	keyPath         string
	caCrtPath       string
	caCRLPath       string
)

func TestMain(m *testing.M) {
	logFilePath = filepath.Join(configDir, "sftpgo_webdavd_test.log")
	logger.InitLogger(logFilePath, 5, 1, 28, false, false, zerolog.DebugLevel)
	os.Setenv("SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN", "1")
	os.Setenv("SFTPGO_COMMON__ALLOW_SELF_CONNECTIONS", "1")
	os.Setenv("SFTPGO_DEFAULT_ADMIN_USERNAME", "admin")
	os.Setenv("SFTPGO_DEFAULT_ADMIN_PASSWORD", "password")
	os.Setenv("SFTPGO_WEBDAVD__CACHE__MIME_TYPES__CUSTOM_MAPPINGS__0__EXT", ".sftpgo")
	os.Setenv("SFTPGO_WEBDAVD__CACHE__MIME_TYPES__CUSTOM_MAPPINGS__0__MIME", "application/sftpgo")
	err := config.LoadConfig(configDir, "")
	if err != nil {
		logger.ErrorToConsole("error loading configuration: %v", err)
		os.Exit(1)
	}
	providerConf := config.GetProviderConf()
	logger.InfoToConsole("Starting WebDAVD tests, provider: %v", providerConf.Driver)
	commonConf := config.GetCommonConfig()
	commonConf.UploadMode = 2
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

	certPath = filepath.Join(os.TempDir(), "test_dav.crt")
	keyPath = filepath.Join(os.TempDir(), "test_dav.key")
	caCrtPath = filepath.Join(os.TempDir(), "test_dav_ca.crt")
	caCRLPath = filepath.Join(os.TempDir(), "test_dav_crl.crt")
	err = os.WriteFile(certPath, []byte(webDavCert), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing WebDAV certificate: %v", err)
		os.Exit(1)
	}
	err = os.WriteFile(keyPath, []byte(webDavKey), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing WebDAV private key: %v", err)
		os.Exit(1)
	}
	err = os.WriteFile(caCrtPath, []byte(caCRT), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing WebDAV CA crt: %v", err)
		os.Exit(1)
	}
	err = os.WriteFile(caCRLPath, []byte(caCRL), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing WebDAV CRL: %v", err)
		os.Exit(1)
	}

	err = dataprovider.Initialize(providerConf, configDir, true)
	if err != nil {
		logger.ErrorToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}

	err = common.Initialize(commonConf, 0)
	if err != nil {
		logger.WarnToConsole("error initializing common: %v", err)
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

	httpdConf := config.GetHTTPDConfig()
	httpdConf.Bindings[0].Port = 8078
	httpdtest.SetBaseURL("http://127.0.0.1:8078")

	// required to test sftpfs
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Bindings = []sftpd.Binding{
		{
			Port: 9022,
		},
	}
	hostKeyPath := filepath.Join(os.TempDir(), "id_ecdsa")
	sftpdConf.HostKeys = []string{hostKeyPath}

	webDavConf := config.GetWebDAVDConfig()
	webDavConf.CACertificates = []string{caCrtPath}
	webDavConf.CARevocationLists = []string{caCRLPath}
	webDavConf.Bindings = []webdavd.Binding{
		{
			Port: webDavServerPort,
		},
		{
			Port:               webDavTLSServerPort,
			EnableHTTPS:        true,
			CertificateFile:    certPath,
			CertificateKeyFile: keyPath,
			ClientAuthType:     2,
		},
	}
	webDavConf.Cors = webdavd.CorsConfig{
		Enabled:        true,
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}

	status := webdavd.GetStatus()
	if status.IsActive {
		logger.ErrorToConsole("webdav server is already active")
		os.Exit(1)
	}

	extAuthPath = filepath.Join(homeBasePath, "extauth.sh")
	preLoginPath = filepath.Join(homeBasePath, "prelogin.sh")
	postConnectPath = filepath.Join(homeBasePath, "postconnect.sh")
	preDownloadPath = filepath.Join(homeBasePath, "predownload.sh")
	preUploadPath = filepath.Join(homeBasePath, "preupload.sh")

	go func() {
		logger.Debug(logSender, "", "initializing WebDAV server with config %+v", webDavConf)
		if err := webDavConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start WebDAV server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := httpdConf.Initialize(configDir, 0); err != nil {
			logger.ErrorToConsole("could not start HTTP server: %v", err)
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

	waitTCPListening(webDavConf.Bindings[0].GetAddress())
	waitTCPListening(webDavConf.Bindings[1].GetAddress())
	waitTCPListening(httpdConf.Bindings[0].GetAddress())
	waitTCPListening(sftpdConf.Bindings[0].GetAddress())
	webdavd.ReloadCertificateMgr() //nolint:errcheck

	exitCode := m.Run()
	os.Remove(logFilePath)
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

func TestInitialization(t *testing.T) {
	cfg := webdavd.Configuration{
		Bindings: []webdavd.Binding{
			{
				Port:        1234,
				EnableHTTPS: true,
			},
			{
				Port: 0,
			},
		},
		CertificateFile:    "missing path",
		CertificateKeyFile: "bad path",
	}
	err := cfg.Initialize(configDir)
	assert.Error(t, err)

	cfg.Cache = config.GetWebDAVDConfig().Cache
	cfg.Bindings[0].Port = webDavServerPort
	cfg.CertificateFile = certPath
	cfg.CertificateKeyFile = keyPath
	err = cfg.Initialize(configDir)
	assert.Error(t, err)
	err = webdavd.ReloadCertificateMgr()
	assert.NoError(t, err)

	cfg.Bindings = []webdavd.Binding{
		{
			Port: 0,
		},
	}
	err = cfg.Initialize(configDir)
	assert.EqualError(t, err, common.ErrNoBinding.Error())

	cfg.CertificateFile = certPath
	cfg.CertificateKeyFile = keyPath
	cfg.CACertificates = []string{""}

	cfg.Bindings = []webdavd.Binding{
		{
			Port:           9022,
			ClientAuthType: 1,
			EnableHTTPS:    true,
		},
	}
	err = cfg.Initialize(configDir)
	assert.Error(t, err)

	cfg.CACertificates = nil
	cfg.CARevocationLists = []string{""}
	err = cfg.Initialize(configDir)
	assert.Error(t, err)

	cfg.CARevocationLists = nil
	err = cfg.Initialize(configDir)
	assert.Error(t, err)

	cfg.CertificateFile = certPath
	cfg.CertificateKeyFile = keyPath
	cfg.CACertificates = []string{caCrtPath}
	cfg.CARevocationLists = []string{caCRLPath}
	cfg.Bindings[0].ProxyAllowed = []string{"not valid"}
	err = cfg.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is not a valid IP address")
	}
	cfg.Bindings[0].ProxyAllowed = nil
	err = cfg.Initialize(configDir)
	assert.Error(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = cfg.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to load config from provider")
	}
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestBasicHandling(t *testing.T) {
	u := getTestUser()
	u.QuotaSize = 6553600
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	u.QuotaSize = 6553600
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		client := getWebDavClient(user, true, nil)
		assert.NoError(t, checkBasicFunc(client))
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		expectedQuotaSize := testFileSize
		expectedQuotaFiles := 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), user.FirstUpload)
		assert.Equal(t, int64(0), user.FirstDownload)
		err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
			true, testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, user.FirstUpload, int64(0))
		assert.Greater(t, user.FirstDownload, int64(0)) // webdav read the mime type
		// overwrite an existing file
		err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
			true, testFileSize, client)
		assert.NoError(t, err)
		// wrong password
		err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword+"1",
			true, testFileSize, client)
		assert.Error(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		assert.Greater(t, user.FirstUpload, int64(0))
		assert.Greater(t, user.FirstDownload, int64(0))
		err = client.Rename(testFileName, testFileName+"1", false)
		assert.NoError(t, err)
		_, err = client.Stat(testFileName)
		assert.Error(t, err)
		// the webdav client hide the error we check the quota
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		err = client.Remove(testFileName + "1")
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize-testFileSize, user.UsedQuotaSize)
		err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.Error(t, err)

		testDir := "testdir"
		err = client.Mkdir(testDir, os.ModePerm)
		assert.NoError(t, err)
		err = client.MkdirAll(path.Join(testDir, "sub", "sub"), os.ModePerm)
		assert.NoError(t, err)
		err = client.MkdirAll(path.Join(testDir, "sub1", "sub1"), os.ModePerm)
		assert.NoError(t, err)
		err = client.MkdirAll(path.Join(testDir, "sub2", "sub2"), os.ModePerm)
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath, path.Join(testDir, testFileName+".txt"),
			user.Username, defaultPassword, true, testFileSize, client)
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath, path.Join(testDir, testFileName),
			user.Username, defaultPassword, true, testFileSize, client)
		assert.NoError(t, err)
		files, err := client.ReadDir(testDir)
		assert.NoError(t, err)
		assert.Len(t, files, 5)
		err = client.Copy(testDir, testDir+"_copy", false) //nolint:goconst
		assert.NoError(t, err)
		err = client.RemoveAll(testDir)
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
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
		1*time.Second, 100*time.Millisecond)
	status := webdavd.GetStatus()
	assert.True(t, status.IsActive)
}

func TestBasicHandlingCryptFs(t *testing.T) {
	u := getTestUserWithCryptFs()
	u.QuotaSize = 6553600
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))

	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	encryptedFileSize, err := getEncryptedFileSize(testFileSize)
	assert.NoError(t, err)
	expectedQuotaSize := user.UsedQuotaSize + encryptedFileSize
	expectedQuotaFiles := user.UsedQuotaFiles + 1
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName,
		user.Username, defaultPassword, false, testFileSize, client)
	assert.NoError(t, err)
	// overwrite an existing file
	err = uploadFileWithRawClient(testFilePath, testFileName,
		user.Username, defaultPassword, false, testFileSize, client)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	files, err := client.ReadDir("/")
	assert.NoError(t, err)
	if assert.Len(t, files, 1) {
		assert.Equal(t, testFileSize, files[0].Size())
	}
	err = client.Remove(testFileName)
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize-encryptedFileSize, user.UsedQuotaSize)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.Error(t, err)
	testDir := "testdir"
	err = client.Mkdir(testDir, os.ModePerm)
	assert.NoError(t, err)
	err = client.MkdirAll(path.Join(testDir, "sub", "sub"), os.ModePerm)
	assert.NoError(t, err)
	err = client.MkdirAll(path.Join(testDir, "sub1", "sub1"), os.ModePerm)
	assert.NoError(t, err)
	err = client.MkdirAll(path.Join(testDir, "sub2", "sub2"), os.ModePerm)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(testDir, testFileName+".txt"),
		user.Username, defaultPassword, false, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(testDir, testFileName),
		user.Username, defaultPassword, false, testFileSize, client)
	assert.NoError(t, err)
	files, err = client.ReadDir(testDir)
	assert.NoError(t, err)
	assert.Len(t, files, 5)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), testFileName) {
			assert.Equal(t, testFileSize, f.Size())
		} else {
			assert.True(t, f.IsDir())
		}
	}
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
		1*time.Second, 100*time.Millisecond)
}

func TestBufferedUser(t *testing.T) {
	u := getTestUser()
	u.FsConfig.OSConfig = sdk.OSFsConfig{
		WriteBufferSize: 2,
		ReadBufferSize:  1,
	}
	vdirPath := "/crypted"
	mappedPath := filepath.Join(os.TempDir(), util.GenerateUniqueID())
	folderName := filepath.Base(mappedPath)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderName,
		},
		VirtualPath: vdirPath,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	f := vfs.BaseVirtualFolder{
		Name:       folderName,
		MappedPath: mappedPath,
		FsConfig: vfs.Filesystem{
			Provider: sdk.CryptedFilesystemProvider,
			CryptConfig: vfs.CryptFsConfig{
				OSFsConfig: sdk.OSFsConfig{
					WriteBufferSize: 3,
					ReadBufferSize:  2,
				},
				Passphrase: kms.NewPlainSecret(defaultPassword),
			},
		},
	}
	_, _, err := httpdtest.AddFolder(f, http.StatusCreated)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	client := getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))

	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName,
		user.Username, defaultPassword, false, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(vdirPath, testFileName),
		user.Username, defaultPassword, false, testFileSize, client)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.NoError(t, err)
	err = downloadFile(path.Join(vdirPath, testFileName), localDownloadPath, testFileSize, client)
	assert.NoError(t, err)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestLoginEmptyPassword(t *testing.T) {
	u := getTestUser()
	u.Password = ""
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	user.Password = emptyPwdPlaceholder
	client := getWebDavClient(user, false, nil)
	err = checkBasicFunc(client)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "401")
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestAnonymousUser(t *testing.T) {
	u := getTestUser()
	u.Password = ""
	u.Filters.IsAnonymous = true
	_, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.Error(t, err)
	user, _, err := httpdtest.GetUserByUsername(u.Username, http.StatusOK)
	assert.NoError(t, err)

	client := getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))

	user.Password = emptyPwdPlaceholder
	client = getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))

	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		false, testFileSize, client)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "403")
	}
	err = client.Mkdir("testdir", os.ModePerm)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "403")
	}

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLockAfterDelete(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	client := getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		false, testFileSize, client)
	assert.NoError(t, err)
	lockBody := `<?xml version="1.0" encoding="utf-8" ?><d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>`
	req, err := http.NewRequest("LOCK", fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName), bytes.NewReader([]byte(lockBody)))
	assert.NoError(t, err)
	req.SetBasicAuth(u.Username, u.Password)
	req.Header.Set("Timeout", "Second-3600")
	httpClient := httpclient.GetHTTPClient()
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	response, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	re := regexp.MustCompile(`\<D:locktoken><D:href>.*</D:href>`)
	lockToken := string(re.Find(response))
	lockToken = strings.Replace(lockToken, "<D:locktoken><D:href>", "", 1)
	lockToken = strings.Replace(lockToken, "</D:href>", "", 1)
	err = resp.Body.Close()
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodDelete, fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName), nil)
	assert.NoError(t, err)
	req.Header.Set("If", fmt.Sprintf("(%v)", lockToken))
	req.SetBasicAuth(u.Username, u.Password)
	resp, err = httpClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)
	// if we try to lock again it must succeed, the lock must be deleted with the object
	req, err = http.NewRequest("LOCK", fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName), bytes.NewReader([]byte(lockBody)))
	assert.NoError(t, err)
	req.SetBasicAuth(u.Username, u.Password)
	resp, err = httpClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestMtimeHeader(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	client := getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		false, testFileSize, client, dataprovider.KeyValue{Key: ocMtimeHeader, Value: "1668879480"})
	assert.NoError(t, err)
	// check the modification time
	info, err := client.Stat(testFileName)
	if assert.NoError(t, err) {
		assert.Equal(t, time.Unix(1668879480, 0).UTC(), info.ModTime().UTC())
	}
	// test on overwrite
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		false, testFileSize, client, dataprovider.KeyValue{Key: ocMtimeHeader, Value: "1667879480"})
	assert.NoError(t, err)
	info, err = client.Stat(testFileName)
	if assert.NoError(t, err) {
		assert.Equal(t, time.Unix(1667879480, 0).UTC(), info.ModTime().UTC())
	}
	// invalid time will be silently ignored and the time set to now
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		false, testFileSize, client, dataprovider.KeyValue{Key: ocMtimeHeader, Value: "not unix time"})
	assert.NoError(t, err)
	info, err = client.Stat(testFileName)
	if assert.NoError(t, err) {
		assert.NotEqual(t, time.Unix(1667879480, 0).UTC(), info.ModTime().UTC())
	}

	req, err := http.NewRequest("MOVE", fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName), nil)
	assert.NoError(t, err)
	req.Header.Set("Overwrite", "T")
	req.Header.Set("Destination", path.Join("/", testFileName+"rename"))
	req.Header.Set(ocMtimeHeader, "1666779480")
	req.SetBasicAuth(u.Username, u.Password)
	httpClient := httpclient.GetHTTPClient()
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)
	// check the modification time
	info, err = client.Stat(testFileName + "rename")
	if assert.NoError(t, err) {
		assert.Equal(t, time.Unix(1666779480, 0).UTC(), info.ModTime().UTC())
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRenameWithLock(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	client := getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		false, testFileSize, client)
	assert.NoError(t, err)

	lockBody := `<?xml version="1.0" encoding="utf-8" ?><d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>`
	req, err := http.NewRequest("LOCK", fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName), bytes.NewReader([]byte(lockBody)))
	assert.NoError(t, err)
	req.SetBasicAuth(u.Username, u.Password)
	httpClient := httpclient.GetHTTPClient()
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	response, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	re := regexp.MustCompile(`\<D:locktoken><D:href>.*</D:href>`)
	lockToken := string(re.Find(response))
	lockToken = strings.Replace(lockToken, "<D:locktoken><D:href>", "", 1)
	lockToken = strings.Replace(lockToken, "</D:href>", "", 1)
	err = resp.Body.Close()
	assert.NoError(t, err)
	// MOVE with a lock should succeeded
	req, err = http.NewRequest("MOVE", fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName), nil)
	assert.NoError(t, err)
	req.Header.Set("If", fmt.Sprintf("(%v)", lockToken))
	req.Header.Set("Overwrite", "T")
	req.Header.Set("Destination", path.Join("/", testFileName+"1"))
	req.SetBasicAuth(u.Username, u.Password)
	resp, err = httpClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	err = resp.Body.Close()
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPropPatch(t *testing.T) {
	u := getTestUser()
	u.Username = u.Username + "1"
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser := getTestSFTPUser()
	sftpUser.FsConfig.SFTPConfig.Username = localUser.Username

	for _, u := range []dataprovider.User{getTestUser(), getTestUserWithCryptFs(), sftpUser} {
		user, _, err := httpdtest.AddUser(u, http.StatusCreated)
		assert.NoError(t, err)
		client := getWebDavClient(user, true, nil)
		assert.NoError(t, checkBasicFunc(client), sftpUser.Username)

		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
			false, testFileSize, client)
		assert.NoError(t, err)
		httpClient := httpclient.GetHTTPClient()
		propatchBody := `<?xml version="1.0" encoding="utf-8" ?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop><Z:Win32CreationTime>Wed, 04 Nov 2020 13:25:51 GMT</Z:Win32CreationTime><Z:Win32LastAccessTime>Sat, 05 Dec 2020 21:16:12 GMT</Z:Win32LastAccessTime><Z:Win32LastModifiedTime>Wed, 04 Nov 2020 13:25:51 GMT</Z:Win32LastModifiedTime><Z:Win32FileAttributes>00000000</Z:Win32FileAttributes></D:prop></D:set></D:propertyupdate>`
		req, err := http.NewRequest("PROPPATCH", fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName), bytes.NewReader([]byte(propatchBody)))
		assert.NoError(t, err)
		req.SetBasicAuth(u.Username, u.Password)
		resp, err := httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)
		err = resp.Body.Close()
		assert.NoError(t, err)
		info, err := client.Stat(testFileName)
		if assert.NoError(t, err) {
			expected, err := http.ParseTime("Wed, 04 Nov 2020 13:25:51 GMT")
			assert.NoError(t, err)
			assert.Equal(t, testFileSize, info.Size())
			assert.Equal(t, expected.Format(http.TimeFormat), info.ModTime().Format(http.TimeFormat))
		}
		// wrong date
		propatchBody = `<?xml version="1.0" encoding="utf-8" ?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop><Z:Win32CreationTime>Wed, 04 Nov 2020 13:25:51 GMT</Z:Win32CreationTime><Z:Win32LastAccessTime>Sat, 05 Dec 2020 21:16:12 GMT</Z:Win32LastAccessTime><Z:Win32LastModifiedTime>Wid, 04 Nov 2020 13:25:51 GMT</Z:Win32LastModifiedTime><Z:Win32FileAttributes>00000000</Z:Win32FileAttributes></D:prop></D:set></D:propertyupdate>`
		req, err = http.NewRequest("PROPPATCH", fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName), bytes.NewReader([]byte(propatchBody)))
		assert.NoError(t, err)
		req.SetBasicAuth(u.Username, u.Password)
		resp, err = httpClient.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)
		err = resp.Body.Close()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		_, err = httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
		1*time.Second, 100*time.Millisecond)
}

func TestLoginInvalidPwd(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))
	user.Password = "wrong"
	client = getWebDavClient(user, false, nil)
	assert.Error(t, checkBasicFunc(client))
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestLoginNonExistentUser(t *testing.T) {
	user := getTestUser()
	client := getWebDavClient(user, true, nil)
	assert.Error(t, checkBasicFunc(client))
}

func TestRateLimiter(t *testing.T) {
	oldConfig := config.GetCommonConfig()

	cfg := config.GetCommonConfig()
	cfg.RateLimitersConfig = []common.RateLimiterConfig{
		{
			Average:   1,
			Period:    1000,
			Burst:     3,
			Type:      1,
			Protocols: []string{common.ProtocolWebDAV},
		},
	}

	err := common.Initialize(cfg, 0)
	assert.NoError(t, err)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))

	_, err = client.ReadDir(".")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "429")
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
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
	cfg.DefenderConfig.ScoreValid = 1

	err := common.Initialize(cfg, 0)
	assert.NoError(t, err)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, true, nil)
	assert.NoError(t, checkBasicFunc(client))

	user.Password = "wrong_pwd"
	client = getWebDavClient(user, false, nil)
	assert.Error(t, checkBasicFunc(client))
	hosts, _, err := httpdtest.GetDefenderHosts(http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, hosts, 1) {
		host := hosts[0]
		assert.Empty(t, host.GetBanTime())
		assert.Equal(t, 1, host.Score)
	}

	for i := 0; i < 2; i++ {
		client = getWebDavClient(user, false, nil)
		assert.Error(t, checkBasicFunc(client))
	}

	user.Password = defaultPassword
	client = getWebDavClient(user, true, nil)
	err = checkBasicFunc(client)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "403")
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = common.Initialize(oldConfig, 0)
	assert.NoError(t, err)
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
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	client := getWebDavClient(u, false, nil)
	assert.NoError(t, checkBasicFunc(client))
	u.Username = defaultUsername + "1"
	client = getWebDavClient(u, false, nil)
	assert.Error(t, checkBasicFunc(client))
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

func TestExternalAuthPasswordChange(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser()
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, defaultPassword), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	client := getWebDavClient(u, false, nil)
	assert.NoError(t, checkBasicFunc(client))
	u.Username = defaultUsername + "1"
	client = getWebDavClient(u, false, nil)
	assert.Error(t, checkBasicFunc(client))
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, defaultPassword+"1"), os.ModePerm)
	assert.NoError(t, err)
	client = getWebDavClient(u, false, nil)
	assert.Error(t, checkBasicFunc(client))
	u.Password = defaultPassword + "1"
	client = getWebDavClient(u, false, nil)
	assert.NoError(t, checkBasicFunc(client))
	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, defaultUsername, user.Username)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	user, _, err = httpdtest.GetUserByUsername(defaultUsername+"1", http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
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

func TestExternalAuthReturningAnonymousUser(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser()
	u.Filters.IsAnonymous = true
	u.Filters.DeniedProtocols = []string{common.ProtocolSSH}
	u.Password = ""
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	client := getWebDavClient(u, false, nil)
	assert.NoError(t, checkBasicFunc(client))

	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, u.Username, emptyPwdPlaceholder,
		false, testFileSize, client)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "403")
	}

	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.True(t, user.Filters.IsAnonymous)
	assert.Equal(t, []string{dataprovider.PermListItems, dataprovider.PermDownload}, user.Permissions["/"])
	assert.Equal(t, []string{common.ProtocolSSH, common.ProtocolHTTP}, user.Filters.DeniedProtocols)
	assert.Equal(t, []string{dataprovider.SSHLoginMethodPublicKey, dataprovider.SSHLoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive, dataprovider.SSHLoginMethodKeyAndPassword,
		dataprovider.SSHLoginMethodKeyAndKeyboardInt, dataprovider.LoginMethodTLSCertificate,
		dataprovider.LoginMethodTLSCertificateAndPwd}, user.Filters.DeniedLoginMethods)

	u.Password = emptyPwdPlaceholder
	client = getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))

	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		false, testFileSize, client)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "403")
	}
	err = client.Mkdir("testdir", os.ModePerm)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "403")
	}

	err = os.Remove(testFilePath)
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
	err = os.Remove(extAuthPath)
	assert.NoError(t, err)
}

func TestExternalAuthAnonymousGroupInheritance(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	g := dataprovider.Group{
		BaseGroup: sdk.BaseGroup{
			Name: "test_group",
		},
		UserSettings: dataprovider.GroupUserSettings{
			BaseGroupUserSettings: sdk.BaseGroupUserSettings{
				Permissions: map[string][]string{
					"/": allPerms,
				},
				Filters: sdk.BaseUserFilters{
					IsAnonymous: true,
				},
			},
		},
	}
	u := getTestUser()
	u.Groups = []sdk.GroupMapping{
		{
			Name: g.Name,
			Type: sdk.GroupTypePrimary,
		},
	}
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	group, _, err := httpdtest.AddGroup(g, http.StatusCreated)
	assert.NoError(t, err)

	u.Password = emptyPwdPlaceholder
	client := getWebDavClient(u, false, nil)
	assert.NoError(t, checkBasicFunc(client))

	err = client.Mkdir("tdir", os.ModePerm)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "403")
	}

	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.False(t, user.Filters.IsAnonymous)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveGroup(group, http.StatusOK)
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
	client := getWebDavClient(u, true, nil)
	assert.NoError(t, checkBasicFunc(client))

	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	// test login with an existing user
	client = getWebDavClient(user, true, nil)
	assert.NoError(t, checkBasicFunc(client))
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(user, true), os.ModePerm)
	assert.NoError(t, err)
	// update the user to remove it from the cache
	user.FsConfig.Provider = sdk.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret(defaultPassword)
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client = getWebDavClient(user, true, nil)
	assert.Error(t, checkBasicFunc(client))
	// update the user to remove it from the cache
	user.FsConfig.Provider = sdk.LocalFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = nil
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	user.Status = 0
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(user, false), os.ModePerm)
	assert.NoError(t, err)
	client = getWebDavClient(user, true, nil)
	assert.Error(t, checkBasicFunc(client))

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

	client := getWebDavClient(user, true, nil)
	assert.NoError(t, checkBasicFunc(client))
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		true, testFileSize, client)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)

	err = os.WriteFile(preDownloadPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.Error(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
		1*time.Second, 100*time.Millisecond)

	common.Config.Actions.ExecuteOn = []string{common.OperationPreDownload}
	common.Config.Actions.Hook = preDownloadPath

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

	client := getWebDavClient(user, true, nil)
	assert.NoError(t, checkBasicFunc(client))
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		true, testFileSize, client)
	assert.NoError(t, err)

	err = os.WriteFile(preUploadPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)

	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		true, testFileSize, client)
	assert.Error(t, err)

	err = uploadFileWithRawClient(testFilePath, testFileName+"1", user.Username, defaultPassword,
		false, testFileSize, client)
	assert.Error(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
		1*time.Second, 100*time.Millisecond)

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
	client := getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))
	err = os.WriteFile(postConnectPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	assert.Error(t, checkBasicFunc(client))

	common.Config.PostConnectHook = "http://127.0.0.1:8078/healthz"
	assert.NoError(t, checkBasicFunc(client))

	common.Config.PostConnectHook = "http://127.0.0.1:8078/notfound"
	assert.Error(t, checkBasicFunc(client))

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.PostConnectHook = ""
}

func TestMaxConnections(t *testing.T) {
	oldValue := common.Config.MaxTotalConnections
	common.Config.MaxTotalConnections = 1

	assert.Eventually(t, func() bool {
		return common.Connections.GetClientConnections() == 0
	}, 1000*time.Millisecond, 50*time.Millisecond)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, true, nil)
	assert.NoError(t, checkBasicFunc(client))
	// now add a fake connection
	fs := vfs.NewOsFs("id", os.TempDir(), "", nil)
	connection := &webdavd.Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}
	err = common.Connections.Add(connection)
	assert.NoError(t, err)
	assert.Error(t, checkBasicFunc(client))
	common.Connections.Remove(connection.GetID())
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
		1*time.Second, 100*time.Millisecond)

	common.Config.MaxTotalConnections = oldValue
}

func TestMaxPerHostConnections(t *testing.T) {
	oldValue := common.Config.MaxPerHostConnections
	common.Config.MaxPerHostConnections = 1

	assert.Eventually(t, func() bool {
		return common.Connections.GetClientConnections() == 0
	}, 1000*time.Millisecond, 50*time.Millisecond)

	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, true, nil)
	assert.NoError(t, checkBasicFunc(client))
	// now add a fake connection
	addrs, err := net.LookupHost("localhost")
	assert.NoError(t, err)
	for _, addr := range addrs {
		common.Connections.AddClientConnection(addr)
	}
	assert.Error(t, checkBasicFunc(client))
	for _, addr := range addrs {
		common.Connections.RemoveClientConnection(addr)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
		1*time.Second, 100*time.Millisecond)

	common.Config.MaxPerHostConnections = oldValue
}

func TestMustChangePasswordRequirement(t *testing.T) {
	u := getTestUser()
	u.Filters.RequirePasswordChange = true
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	client := getWebDavClient(user, false, nil)
	assert.Error(t, checkBasicFunc(client))

	err = dataprovider.UpdateUserPassword(user.Username, defaultPassword, "", "", "")
	assert.NoError(t, err)

	client = getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestMaxSessions(t *testing.T) {
	u := getTestUser()
	u.MaxSessions = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))
	// now add a fake connection
	fs := vfs.NewOsFs("id", os.TempDir(), "", nil)
	connection := &webdavd.Connection{
		BaseConnection: common.NewBaseConnection(fs.ConnectionID(), common.ProtocolWebDAV, "", "", user),
	}
	err = common.Connections.Add(connection)
	assert.NoError(t, err)
	assert.Error(t, checkBasicFunc(client))
	common.Connections.Remove(connection.GetID())
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
		1*time.Second, 100*time.Millisecond)
}

func TestLoginWithIPilters(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedIP = []string{"192.167.0.0/24", "172.18.0.0/16"}
	u.Filters.AllowedIP = []string{"172.19.0.0/16"}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, true, nil)
	assert.Error(t, checkBasicFunc(client))

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
	// use an unknown mime to trigger content type detection
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/sub2",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{"*.jpg", "*.zipp"},
		},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, false, nil)
	testFilePath1 := filepath.Join(user.HomeDir, subDir1, "file.zipp")
	testFilePath2 := filepath.Join(user.HomeDir, subDir2, "file.zipp")
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
	err = downloadFile(path.Join("/", subDir1, "file.zipp"), localDownloadPath, 5, client)
	assert.Error(t, err)
	err = downloadFile(path.Join("/", subDir2, "file.zipp"), localDownloadPath, 5, client)
	assert.Error(t, err)
	err = downloadFile(path.Join("/", subDir2, "file.jpg"), localDownloadPath, 5, client)
	assert.Error(t, err)
	err = downloadFile(path.Join("missing.zip"), localDownloadPath, 5, client)
	assert.Error(t, err)

	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
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
	// we need download permission to get size since PROPFIND will open the file
	u.Permissions[path.Join("/", subDir1)] = []string{dataprovider.PermListItems, dataprovider.PermDownload}
	u.Permissions[path.Join("/", subDir2)] = []string{dataprovider.PermListItems, dataprovider.PermUpload,
		dataprovider.PermDelete, dataprovider.PermDownload}
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/sub2",
			AllowedPatterns: []string{},
			DeniedPatterns:  []string{"*.zip"},
		},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, true, nil)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := user.QuotaSize
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = client.Mkdir(subDir1, os.ModePerm)
	assert.NoError(t, err)
	err = client.Mkdir(subDir2, os.ModePerm)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(subDir1, testFileName), user.Username,
		defaultPassword, true, testFileSize, client)
	assert.Error(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(subDir2, testFileName+".zip"), user.Username,
		defaultPassword, true, testFileSize, client)

	assert.Error(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(subDir2, testFileName), user.Username,
		defaultPassword, true, testFileSize, client)
	assert.NoError(t, err)
	err = client.Rename(path.Join(subDir2, testFileName), path.Join(subDir1, testFileName), false)
	assert.Error(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(subDir2, testFileName), user.Username,
		defaultPassword, true, testFileSize, client)
	assert.Error(t, err)
	err = uploadFileWithRawClient(testFilePath, subDir1, user.Username,
		defaultPassword, true, testFileSize, client)
	assert.Error(t, err)
	// overquota
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		true, testFileSize, client)
	assert.Error(t, err)
	err = client.Remove(path.Join(subDir2, testFileName))
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		true, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		true, testFileSize, client)
	assert.Error(t, err)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDeniedLoginMethod(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, true, nil)
	assert.Error(t, checkBasicFunc(client))

	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPublicKey, dataprovider.SSHLoginMethodKeyAndKeyboardInt}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client = getWebDavClient(user, true, nil)
	assert.NoError(t, checkBasicFunc(client))

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDeniedProtocols(t *testing.T) {
	u := getTestUser()
	u.Filters.DeniedProtocols = []string{common.ProtocolWebDAV}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, false, nil)
	assert.Error(t, checkBasicFunc(client))

	user.Filters.DeniedProtocols = []string{common.ProtocolSSH, common.ProtocolFTP}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client = getWebDavClient(user, false, nil)
	assert.NoError(t, checkBasicFunc(client))

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
		testFileSize := int64(65536)
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
		client := getWebDavClient(user, false, nil)
		// test quota files
		err = uploadFileWithRawClient(testFilePath, testFileName+".quota", user.Username, defaultPassword, false, //nolint:goconst
			testFileSize, client)
		if !assert.NoError(t, err, "username: %v", user.Username) {
			info, err := os.Stat(testFilePath)
			if assert.NoError(t, err) {
				fmt.Printf("local file size: %v\n", info.Size())
			}
			printLatestLogs(20)
		}
		err = uploadFileWithRawClient(testFilePath, testFileName+".quota1", user.Username, defaultPassword,
			false, testFileSize, client)
		assert.Error(t, err, "username: %v", user.Username)
		err = client.Rename(testFileName+".quota", testFileName, false)
		assert.NoError(t, err)
		files, err := client.ReadDir("/")
		assert.NoError(t, err)
		assert.Len(t, files, 1)
		// test quota size
		user.QuotaSize = testFileSize - 1
		user.QuotaFiles = 0
		user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath, testFileName+".quota", user.Username, defaultPassword,
			false, testFileSize, client)
		assert.Error(t, err)
		err = client.Rename(testFileName, testFileName+".quota", false)
		assert.NoError(t, err)
		// now test quota limits while uploading the current file, we have 1 bytes remaining
		user.QuotaSize = testFileSize + 1
		user.QuotaFiles = 0
		user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath1, testFileName1, user.Username, defaultPassword,
			false, testFileSize1, client)
		assert.Error(t, err)
		_, err = client.Stat(testFileName1)
		assert.Error(t, err)
		err = client.Rename(testFileName+".quota", testFileName, false)
		assert.NoError(t, err)
		// overwriting an existing file will work if the resulting size is lesser or equal than the current one
		err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
			false, testFileSize, client)
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath2, testFileName, user.Username, defaultPassword,
			false, testFileSize2, client)
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath1, testFileName, user.Username, defaultPassword,
			false, testFileSize1, client)
		assert.Error(t, err)
		err = uploadFileWithRawClient(testFilePath2, testFileName, user.Username, defaultPassword,
			false, testFileSize2, client)
		assert.NoError(t, err)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
		err = os.Remove(testFilePath2)
		assert.NoError(t, err)
		if user.Username == defaultUsername {
			err = os.RemoveAll(user.GetHomeDir())
			assert.NoError(t, err)
			_, err = httpdtest.RemoveUser(user, http.StatusOK)
			assert.NoError(t, err)
			user.Password = defaultPassword
			user.ID = 0
			user.CreatedAt = 0
			user.QuotaFiles = 0
			user.QuotaSize = 0
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

func TestTransferQuotaLimits(t *testing.T) {
	u := getTestUser()
	u.DownloadDataTransfer = 1
	u.UploadDataTransfer = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(550000)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	client := getWebDavClient(user, false, nil)
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		false, testFileSize, client)
	assert.NoError(t, err)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.NoError(t, err)
	// error while download is active
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.Error(t, err)
	// error before starting the download
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.Error(t, err)
	// error while upload is active
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		false, testFileSize, client)
	assert.Error(t, err)
	// error before starting the upload
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		false, testFileSize, client)
	assert.Error(t, err)

	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
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
		testFileName1 := "test_file_dav1.dat"
		testFilePath1 := filepath.Join(homeBasePath, testFileName1)
		err = createTestFile(testFilePath1, testFileSize1)
		assert.NoError(t, err)
		client := getWebDavClient(user, false, nil)
		err = uploadFileWithRawClient(testFilePath1, testFileName1, user.Username, defaultPassword,
			false, testFileSize1, client)
		assert.Error(t, err)
		err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
			false, testFileSize, client)
		assert.NoError(t, err)
		// now test overwrite an existing file with a size bigger than the allowed one
		err = createTestFile(filepath.Join(user.GetHomeDir(), testFileName1), testFileSize1)
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath1, testFileName1, user.Username, defaultPassword,
			false, testFileSize1, client)
		assert.Error(t, err)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
		if user.Username == defaultUsername {
			err = os.RemoveAll(user.GetHomeDir())
			assert.NoError(t, err)
			_, err = httpdtest.RemoveUser(user, http.StatusOK)
			assert.NoError(t, err)
			user.Filters.MaxUploadFileSize = 65536000
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

func TestClientClose(t *testing.T) {
	u := getTestUser()
	u.UploadBandwidth = 64
	u.DownloadBandwidth = 64
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	u.UploadBandwidth = 64
	u.DownloadBandwidth = 64
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		testFileSize := int64(1048576)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		client := getWebDavClient(user, true, nil)
		assert.NoError(t, checkBasicFunc(client))

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
				true, testFileSize, client)
			assert.Error(t, err)
			wg.Done()
		}()

		assert.Eventually(t, func() bool {
			for _, stat := range common.Connections.GetStats("") {
				if len(stat.Transfers) > 0 {
					return true
				}
			}
			return false
		}, 1*time.Second, 50*time.Millisecond)

		for _, stat := range common.Connections.GetStats("") {
			common.Connections.Close(stat.ConnectionID, "")
		}
		wg.Wait()
		// for the sftp user a stat is done after the failed upload and
		// this triggers a new connection
		for _, stat := range common.Connections.GetStats("") {
			common.Connections.Close(stat.ConnectionID, "")
		}
		assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
			1*time.Second, 100*time.Millisecond)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		testFilePath = filepath.Join(user.HomeDir, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)

		wg.Add(1)
		go func() {
			err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
			assert.Error(t, err)
			wg.Done()
		}()

		assert.Eventually(t, func() bool {
			for _, stat := range common.Connections.GetStats("") {
				if len(stat.Transfers) > 0 {
					return true
				}
			}
			return false
		}, 1*time.Second, 50*time.Millisecond)

		for _, stat := range common.Connections.GetStats("") {
			common.Connections.Close(stat.ConnectionID, "")
		}
		wg.Wait()
		assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
			1*time.Second, 100*time.Millisecond)

		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginWithDatabaseCredentials(t *testing.T) {
	u := getTestUser()
	u.FsConfig.Provider = sdk.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret(`{ "type": "service_account" }`)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.GCSConfig.Credentials.GetStatus())
	assert.NotEmpty(t, user.FsConfig.GCSConfig.Credentials.GetPayload())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetAdditionalData())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetKey())

	client := getWebDavClient(user, false, nil)

	err = client.Connect()
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginInvalidFs(t *testing.T) {
	u := getTestUser()
	u.FsConfig.Provider = sdk.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("invalid JSON for credentials")
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	client := getWebDavClient(user, true, nil)
	assert.Error(t, checkBasicFunc(client))

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
	u.QuotaFiles = 1000
	u.HomeDir = filepath.Join(os.TempDir(), u.Username)
	u.FsConfig.SFTPConfig.BufferSize = 2
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	client := getWebDavClient(sftpUser, true, nil)
	assert.NoError(t, checkBasicFunc(client))
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	expectedQuotaSize := testFileSize
	expectedQuotaFiles := 1
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, sftpUser.Username, defaultPassword,
		true, testFileSize, client)
	assert.NoError(t, err)
	// overwrite an existing file
	err = uploadFileWithRawClient(testFilePath, testFileName, sftpUser.Username, defaultPassword,
		true, testFileSize, client)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.NoError(t, err)

	user, _, err := httpdtest.GetUserByUsername(sftpUser.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)

	fileContent := []byte("test file contents")
	err = os.WriteFile(testFilePath, fileContent, os.ModePerm)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, sftpUser.Username, defaultPassword,
		true, int64(len(fileContent)), client)
	assert.NoError(t, err)
	remotePath := fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName)
	req, err := http.NewRequest(http.MethodGet, remotePath, nil)
	assert.NoError(t, err)
	httpClient := httpclient.GetHTTPClient()
	req.SetBasicAuth(user.Username, defaultPassword)
	req.Header.Set("Range", "bytes=5-")
	resp, err := httpClient.Do(req)
	if assert.NoError(t, err) {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusPartialContent, resp.StatusCode)
		bodyBytes, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "file contents", string(bodyBytes))
	}
	req.Header.Set("Range", "bytes=5-8")
	resp, err = httpClient.Do(req)
	if assert.NoError(t, err) {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusPartialContent, resp.StatusCode)
		bodyBytes, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "file", string(bodyBytes))
	}

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(sftpUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestBytesRangeRequests(t *testing.T) {
	u := getTestUser()
	u.Username = u.Username + "1"
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser := getTestSFTPUser()
	sftpUser.FsConfig.SFTPConfig.Username = localUser.Username

	for _, u := range []dataprovider.User{getTestUser(), getTestUserWithCryptFs(), sftpUser} {
		user, _, err := httpdtest.AddUser(u, http.StatusCreated)
		assert.NoError(t, err)
		testFileName := "test_file.txt"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		fileContent := []byte("test file contents")
		err = os.WriteFile(testFilePath, fileContent, os.ModePerm)
		assert.NoError(t, err)
		client := getWebDavClient(user, true, nil)
		err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
			true, int64(len(fileContent)), client)
		assert.NoError(t, err)
		remotePath := fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName)
		req, err := http.NewRequest(http.MethodGet, remotePath, nil)
		if assert.NoError(t, err) {
			httpClient := httpclient.GetHTTPClient()
			req.SetBasicAuth(user.Username, defaultPassword)
			req.Header.Set("Range", "bytes=5-")
			resp, err := httpClient.Do(req)
			if assert.NoError(t, err) {
				defer resp.Body.Close()
				assert.Equal(t, http.StatusPartialContent, resp.StatusCode)
				bodyBytes, err := io.ReadAll(resp.Body)
				assert.NoError(t, err)
				assert.Equal(t, "file contents", string(bodyBytes))
			}
			req.Header.Set("Range", "bytes=5-8")
			resp, err = httpClient.Do(req)
			if assert.NoError(t, err) {
				defer resp.Body.Close()
				assert.Equal(t, http.StatusPartialContent, resp.StatusCode)
				bodyBytes, err := io.ReadAll(resp.Body)
				assert.NoError(t, err)
				assert.Equal(t, "file", string(bodyBytes))
			}
		}
		// seek on a missing file
		remotePath = fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName+"_missing")
		req, err = http.NewRequest(http.MethodGet, remotePath, nil)
		if assert.NoError(t, err) {
			httpClient := httpclient.GetHTTPClient()
			req.SetBasicAuth(user.Username, defaultPassword)
			req.Header.Set("Range", "bytes=5-")
			resp, err := httpClient.Do(req)
			if assert.NoError(t, err) {
				defer resp.Body.Close()
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			}
		}

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		_, err = httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestContentTypeGET(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)

	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(64)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	client := getWebDavClient(user, true, nil)
	err = uploadFileWithRawClient(testFilePath, testFileName+".sftpgo", user.Username, defaultPassword,
		true, testFileSize, client)
	assert.NoError(t, err)
	remotePath := fmt.Sprintf("http://%v/%v", webDavServerAddr, testFileName+".sftpgo")
	req, err := http.NewRequest(http.MethodGet, remotePath, nil)
	if assert.NoError(t, err) {
		httpClient := httpclient.GetHTTPClient()
		req.SetBasicAuth(user.Username, defaultPassword)
		resp, err := httpClient.Do(req)
		if assert.NoError(t, err) {
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "application/sftpgo", resp.Header.Get("Content-Type"))
		}
	}

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestHEAD(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	rootPath := fmt.Sprintf("http://%v", webDavServerAddr)
	httpClient := httpclient.GetHTTPClient()
	req, err := http.NewRequest(http.MethodHead, rootPath, nil)
	if assert.NoError(t, err) {
		req.SetBasicAuth(u.Username, u.Password)
		resp, err := httpClient.Do(req)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)
			assert.Equal(t, "text/xml; charset=utf-8", resp.Header.Get("Content-Type"))
			resp.Body.Close()
		}
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestGETAsPROPFIND(t *testing.T) {
	u := getTestUser()
	subDir1 := "/sub1"
	u.Permissions[subDir1] = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	rootPath := fmt.Sprintf("http://%v/", webDavServerAddr)
	httpClient := httpclient.GetHTTPClient()
	req, err := http.NewRequest(http.MethodGet, rootPath, nil)
	if assert.NoError(t, err) {
		req.SetBasicAuth(u.Username, u.Password)
		resp, err := httpClient.Do(req)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)
			resp.Body.Close()
		}
	}
	client := getWebDavClient(user, false, nil)
	err = client.MkdirAll(path.Join(subDir1, "sub", "sub1"), os.ModePerm)
	assert.NoError(t, err)
	subPath := fmt.Sprintf("http://%v/%v", webDavServerAddr, subDir1)
	req, err = http.NewRequest(http.MethodGet, subPath, nil)
	if assert.NoError(t, err) {
		req.SetBasicAuth(u.Username, u.Password)
		resp, err := httpClient.Do(req)
		if assert.NoError(t, err) {
			// before the performance patch we have a 500 here, now we have 207 but an empty list
			//assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
			assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)
			resp.Body.Close()
		}
	}
	// we cannot stat the sub at all
	subPath1 := fmt.Sprintf("http://%v/%v", webDavServerAddr, path.Join(subDir1, "sub"))
	req, err = http.NewRequest(http.MethodGet, subPath1, nil)
	if assert.NoError(t, err) {
		req.SetBasicAuth(u.Username, u.Password)
		resp, err := httpClient.Do(req)
		if assert.NoError(t, err) {
			// here the stat will fail, so the request will not be changed in propfind
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			resp.Body.Close()
		}
	}

	// we have no permission, we get an empty list
	files, err := client.ReadDir(subDir1)
	assert.NoError(t, err)
	assert.Len(t, files, 0)
	// if we grant the permissions the files are listed
	user.Permissions[subDir1] = []string{dataprovider.PermDownload, dataprovider.PermListItems}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	files, err = client.ReadDir(subDir1)
	assert.NoError(t, err)
	assert.Len(t, files, 1)
	// PROPFIND with infinity depth is forbidden
	req, err = http.NewRequest(http.MethodGet, rootPath, nil)
	if assert.NoError(t, err) {
		req.SetBasicAuth(u.Username, u.Password)
		req.Header.Set("Depth", "infinity")
		resp, err := httpClient.Do(req)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			resp.Body.Close()
		}
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestStat(t *testing.T) {
	u := getTestUser()
	u.Permissions["/subdir"] = []string{dataprovider.PermUpload, dataprovider.PermListItems, dataprovider.PermDownload}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, true, nil)
	subDir := "subdir"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = client.Mkdir(subDir, os.ModePerm)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, testFileName, user.Username, defaultPassword,
		true, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join("/", subDir, testFileName), user.Username,
		defaultPassword, true, testFileSize, client)
	assert.NoError(t, err)
	user.Permissions["/subdir"] = []string{dataprovider.PermUpload, dataprovider.PermDownload}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = client.Stat(testFileName)
	assert.NoError(t, err)
	_, err = client.Stat(path.Join("/", subDir, testFileName))
	assert.Error(t, err)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadOverwriteVfolder(t *testing.T) {
	u := getTestUser()
	vdir := "/vdir"
	mappedPath := filepath.Join(os.TempDir(), "mappedDir")
	folderName := filepath.Base(mappedPath)
	f := vfs.BaseVirtualFolder{
		Name:       folderName,
		MappedPath: mappedPath,
	}
	_, _, err := httpdtest.AddFolder(f, http.StatusCreated)
	assert.NoError(t, err)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderName,
		},
		VirtualPath: vdir,
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})
	err = os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, false, nil)
	files, err := client.ReadDir(".")
	assert.NoError(t, err)
	vdirFound := false
	for _, info := range files {
		if info.Name() == path.Base(vdir) {
			vdirFound = true
			break
		}
	}
	assert.True(t, vdirFound)
	info, err := client.Stat(vdir)
	if assert.NoError(t, err) {
		assert.Equal(t, path.Base(vdir), info.Name())
	}

	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(vdir, testFileName), user.Username,
		defaultPassword, true, testFileSize, client)
	assert.NoError(t, err)
	folder, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, testFileSize, folder.UsedQuotaSize)
	assert.Equal(t, 1, folder.UsedQuotaFiles)
	err = uploadFileWithRawClient(testFilePath, path.Join(vdir, testFileName), user.Username,
		defaultPassword, true, testFileSize, client)
	assert.NoError(t, err)
	folder, _, err = httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, testFileSize, folder.UsedQuotaSize)
	assert.Equal(t, 1, folder.UsedQuotaFiles)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestOsErrors(t *testing.T) {
	u := getTestUser()
	vdir := "/vdir"
	mappedPath := filepath.Join(os.TempDir(), "mappedDir")
	folderName := filepath.Base(mappedPath)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderName,
		},
		VirtualPath: vdir,
		QuotaSize:   -1,
		QuotaFiles:  -1,
	})
	f := vfs.BaseVirtualFolder{
		Name:       folderName,
		MappedPath: mappedPath,
	}
	_, _, err := httpdtest.AddFolder(f, http.StatusCreated)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client := getWebDavClient(user, false, nil)
	files, err := client.ReadDir(".")
	assert.NoError(t, err)
	assert.Len(t, files, 1)
	info, err := client.Stat(vdir)
	assert.NoError(t, err)
	assert.True(t, info.IsDir())
	// now remove the folder mapped to vdir. It still appear in directory listing
	// virtual folders are automatically added
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
	files, err = client.ReadDir(".")
	assert.NoError(t, err)
	assert.Len(t, files, 1)
	err = createTestFile(filepath.Join(user.GetHomeDir(), testFileName), 32768)
	assert.NoError(t, err)
	files, err = client.ReadDir(".")
	assert.NoError(t, err)
	if assert.Len(t, files, 2) {
		var names []string
		for _, info := range files {
			names = append(names, info.Name())
		}
		assert.Contains(t, names, testFileName)
		assert.Contains(t, names, "vdir")
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

func TestMiscCommands(t *testing.T) {
	u := getTestUser()
	u.QuotaFiles = 100
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser()
	u.QuotaFiles = 100
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		dir := "testDir"
		client := getWebDavClient(user, true, nil)
		err = client.MkdirAll(path.Join(dir, "sub1", "sub2"), os.ModePerm)
		assert.NoError(t, err)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath, path.Join(dir, testFileName), user.Username,
			defaultPassword, true, testFileSize, client)
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath, path.Join(dir, "sub1", testFileName), user.Username,
			defaultPassword, true, testFileSize, client)
		assert.NoError(t, err)
		err = uploadFileWithRawClient(testFilePath, path.Join(dir, "sub1", "sub2", testFileName), user.Username,
			defaultPassword, true, testFileSize, client)
		assert.NoError(t, err)
		err = client.Copy(dir, dir+"_copy", false)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 6, user.UsedQuotaFiles)
		assert.Equal(t, 6*testFileSize, user.UsedQuotaSize)
		err = client.Copy(dir, dir+"_copy1", false) //nolint:goconst
		assert.NoError(t, err)
		err = client.Copy(dir+"_copy", dir+"_copy1", false)
		assert.Error(t, err)
		err = client.Copy(dir+"_copy", dir+"_copy1", true)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 9, user.UsedQuotaFiles)
		assert.Equal(t, 9*testFileSize, user.UsedQuotaSize)
		err = client.Rename(dir+"_copy1", dir+"_copy2", false)
		assert.NoError(t, err)
		err = client.Remove(path.Join(dir+"_copy", testFileName))
		assert.NoError(t, err)
		err = client.Rename(dir+"_copy2", dir+"_copy", true)
		assert.NoError(t, err)
		err = client.Copy(dir+"_copy", dir+"_copy1", false)
		assert.NoError(t, err)
		err = client.RemoveAll(dir + "_copy1")
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 6, user.UsedQuotaFiles)
		assert.Equal(t, 6*testFileSize, user.UsedQuotaSize)

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
			user.QuotaFiles = 0
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
	client := getWebDavClient(user, true, tlsConfig)
	err = checkBasicFunc(client)
	if assert.Error(t, err) {
		if !strings.Contains(err.Error(), "bad certificate") && !strings.Contains(err.Error(), "broken pipe") {
			t.Errorf("unexpected error: %v", err)
		}
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestClientCertificateAuth(t *testing.T) {
	u := getTestUser()
	u.Username = tlsClient1Username
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword, dataprovider.LoginMethodTLSCertificateAndPwd}
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
	resp, err := getTLSHTTPClient(tlsConfig).Get(fmt.Sprintf("https://%v/", webDavTLSServerAddr))
	if assert.NoError(t, err) {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, string(body))
	}

	user.Filters.TLSUsername = sdk.TLSUsernameCN
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client := getWebDavClient(user, true, tlsConfig)
	err = checkBasicFunc(client)
	assert.NoError(t, err)
	user.Filters.TLSUsername = sdk.TLSUsernameNone
	user.Filters.TLSCerts = []string{client1Crt}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client = getWebDavClient(user, true, tlsConfig)
	err = checkBasicFunc(client)
	assert.NoError(t, err)

	user.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword, dataprovider.LoginMethodTLSCertificate}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client = getWebDavClient(user, true, tlsConfig)
	err = checkBasicFunc(client)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestWrongClientCertificate(t *testing.T) {
	u := getTestUser()
	u.Username = tlsClient2Username
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodTLSCertificateAndPwd}
	u.Filters.TLSUsername = sdk.TLSUsernameCN
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

	// the certificate common name is client1 and it does not exists
	resp, err := getTLSHTTPClient(tlsConfig).Get(fmt.Sprintf("https://%v/", webDavTLSServerAddr))
	if assert.NoError(t, err) {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, string(body))
	}

	user.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword, dataprovider.LoginMethodTLSCertificate}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	// now create client1
	u = getTestUser()
	u.Username = tlsClient1Username
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword, dataprovider.LoginMethodTLSCertificate}
	u.Filters.TLSUsername = sdk.TLSUsernameCN
	user1, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	resp, err = getTLSHTTPClient(tlsConfig).Get(fmt.Sprintf("https://%v:%v@%v/", tlsClient2Username, defaultPassword,
		webDavTLSServerAddr))
	if assert.NoError(t, err) {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, string(body))
		assert.Contains(t, string(body), "invalid credentials")
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user1.GetHomeDir())
	assert.NoError(t, err)
}

func TestClientCertificateAuthCachedUser(t *testing.T) {
	u := getTestUser()
	u.Username = tlsClient1Username
	u.Filters.TLSUsername = sdk.TLSUsernameCN
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodTLSCertificateAndPwd}
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
	client := getWebDavClient(user, true, tlsConfig)
	err = checkBasicFunc(client)
	assert.NoError(t, err)
	// the user is now cached without a password, try a simple password login with and without TLS
	client = getWebDavClient(user, true, nil)
	err = checkBasicFunc(client)
	assert.NoError(t, err)

	client = getWebDavClient(user, false, nil)
	err = checkBasicFunc(client)
	assert.NoError(t, err)

	// and now with a wrong password
	user.Password = "wrong"
	client = getWebDavClient(user, false, nil)
	err = checkBasicFunc(client)
	assert.Error(t, err)

	// allow cert+password only
	user.Password = ""
	user.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodTLSCertificate}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	client = getWebDavClient(user, true, tlsConfig)
	err = checkBasicFunc(client)
	assert.NoError(t, err)
	// the user is now cached
	client = getWebDavClient(user, true, tlsConfig)
	err = checkBasicFunc(client)
	assert.NoError(t, err)
	// password auth should work too
	client = getWebDavClient(user, false, nil)
	err = checkBasicFunc(client)
	assert.NoError(t, err)

	client = getWebDavClient(user, true, nil)
	err = checkBasicFunc(client)
	assert.NoError(t, err)

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
	u.Filters.TLSUsername = sdk.TLSUsernameCN
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodTLSCertificate, dataprovider.LoginMethodPassword}
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // use this for tests only
		MinVersion:         tls.VersionTLS12,
	}
	tlsCert, err := tls.X509KeyPair([]byte(client1Crt), []byte(client1Key))
	assert.NoError(t, err)
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
	client := getWebDavClient(u, true, tlsConfig)
	assert.NoError(t, checkBasicFunc(client))

	resp, err := getTLSHTTPClient(tlsConfig).Get(fmt.Sprintf("https://%v:%v@%v/", tlsClient2Username, defaultPassword,
		webDavTLSServerAddr))
	if assert.NoError(t, err) {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, string(body))
		assert.Contains(t, string(body), "invalid credentials")
	}

	user, _, err := httpdtest.GetUserByUsername(tlsClient1Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, tlsClient1Username, user.Username)
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

func TestPreLoginHookWithClientCert(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser()
	u.Username = tlsClient1Username
	u.Filters.TLSUsername = sdk.TLSUsernameCN
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodTLSCertificate, dataprovider.LoginMethodPassword}
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
	client := getWebDavClient(u, true, tlsConfig)
	assert.NoError(t, checkBasicFunc(client))

	user, _, err := httpdtest.GetUserByUsername(tlsClient1Username, http.StatusOK)
	assert.NoError(t, err)
	// test login with an existing user
	client = getWebDavClient(user, true, tlsConfig)
	assert.NoError(t, checkBasicFunc(client))
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(user, true), os.ModePerm)
	assert.NoError(t, err)
	// update the user to remove it from the cache
	user.Password = defaultPassword
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client = getWebDavClient(user, true, tlsConfig)
	assert.Error(t, checkBasicFunc(client))
	// update the user to remove it from the cache
	user.Password = defaultPassword
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	user.Status = 0
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(user, false), os.ModePerm)
	assert.NoError(t, err)
	client = getWebDavClient(user, true, tlsConfig)
	assert.Error(t, checkBasicFunc(client))

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

func TestSFTPLoopVirtualFolders(t *testing.T) {
	user1 := getTestUser()
	user2 := getTestUser()
	user1.Username += "1"
	user2.Username += "2"
	// user1 is a local account with a virtual SFTP folder to user2
	// user2 has user1 as SFTP fs
	folderName := "sftp"
	user1.VirtualFolders = append(user1.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderName,
		},
		VirtualPath: "/vdir",
	})
	user2.FsConfig.Provider = sdk.SFTPFilesystemProvider
	user2.FsConfig.SFTPConfig = vfs.SFTPFsConfig{
		BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
			Endpoint: sftpServerAddr,
			Username: user1.Username,
		},
		Password: kms.NewPlainSecret(defaultPassword),
	}
	f := vfs.BaseVirtualFolder{
		Name: folderName,
		FsConfig: vfs.Filesystem{
			Provider: sdk.SFTPFilesystemProvider,
			SFTPConfig: vfs.SFTPFsConfig{
				BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
					Endpoint: sftpServerAddr,
					Username: user2.Username,
				},
				Password: kms.NewPlainSecret(defaultPassword),
			},
		},
	}
	_, _, err := httpdtest.AddFolder(f, http.StatusCreated)
	assert.NoError(t, err)

	user1, resp, err := httpdtest.AddUser(user1, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	user2, resp, err = httpdtest.AddUser(user2, http.StatusCreated)
	assert.NoError(t, err, string(resp))

	client := getWebDavClient(user1, true, nil)

	testDir := "tdir"
	err = client.Mkdir(testDir, os.ModePerm)
	assert.NoError(t, err)

	contents, err := client.ReadDir("/")
	assert.NoError(t, err)
	if assert.Len(t, contents, 2) {
		expected := 0
		for _, info := range contents {
			switch info.Name() {
			case testDir, "vdir":
				assert.True(t, info.IsDir())
				expected++
			default:
				t.Errorf("unexpected file/dir %q", info.Name())
			}
		}
		assert.Equal(t, expected, 2)
	}

	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user1.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user2.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
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
		},
		VirtualPath: vdirCryptPath,
	})
	mappedPath := filepath.Join(os.TempDir(), "local")
	folderName := filepath.Base(mappedPath)
	vdirPath := "/vdir/local"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderName,
		},
		VirtualPath: vdirPath,
	})
	mappedPathNested := filepath.Join(os.TempDir(), "nested")
	folderNameNested := filepath.Base(mappedPathNested)
	vdirNestedPath := "/vdir/crypt/nested"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderNameNested,
		},
		VirtualPath: vdirNestedPath,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	f1 := vfs.BaseVirtualFolder{
		Name: folderNameCrypt,
		FsConfig: vfs.Filesystem{
			Provider: sdk.CryptedFilesystemProvider,
			CryptConfig: vfs.CryptFsConfig{
				Passphrase: kms.NewPlainSecret(defaultPassword),
			},
		},
		MappedPath: mappedPathCrypt,
	}
	_, _, err = httpdtest.AddFolder(f1, http.StatusCreated)
	assert.NoError(t, err)
	f2 := vfs.BaseVirtualFolder{
		Name:       folderName,
		MappedPath: mappedPath,
	}
	_, _, err = httpdtest.AddFolder(f2, http.StatusCreated)
	assert.NoError(t, err)
	f3 := vfs.BaseVirtualFolder{
		Name:       folderNameNested,
		MappedPath: mappedPathNested,
	}
	_, _, err = httpdtest.AddFolder(f3, http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	client := getWebDavClient(sftpUser, true, nil)
	assert.NoError(t, checkBasicFunc(client))
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	err = uploadFileWithRawClient(testFilePath, testFileName, sftpUser.Username,
		defaultPassword, true, testFileSize, client)
	assert.NoError(t, err)
	err = downloadFile(testFileName, localDownloadPath, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join("/vdir", testFileName), sftpUser.Username,
		defaultPassword, true, testFileSize, client)
	assert.NoError(t, err)
	err = downloadFile(path.Join("/vdir", testFileName), localDownloadPath, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(vdirPath, testFileName), sftpUser.Username,
		defaultPassword, true, testFileSize, client)
	assert.NoError(t, err)
	err = downloadFile(path.Join(vdirPath, testFileName), localDownloadPath, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(vdirCryptPath, testFileName), sftpUser.Username,
		defaultPassword, true, testFileSize, client)
	assert.NoError(t, err)
	err = downloadFile(path.Join(vdirCryptPath, testFileName), localDownloadPath, testFileSize, client)
	assert.NoError(t, err)
	err = uploadFileWithRawClient(testFilePath, path.Join(vdirNestedPath, testFileName), sftpUser.Username,
		defaultPassword, true, testFileSize, client)
	assert.NoError(t, err)
	err = downloadFile(path.Join(vdirNestedPath, testFileName), localDownloadPath, testFileSize, client)
	assert.NoError(t, err)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
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
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
		1*time.Second, 100*time.Millisecond)
}

func checkBasicFunc(client *gowebdav.Client) error {
	err := client.Connect()
	if err != nil {
		return err
	}
	_, err = client.ReadDir("/")
	return err
}

func checkFileSize(remoteDestPath string, expectedSize int64, client *gowebdav.Client) error {
	info, err := client.Stat(remoteDestPath)
	if err != nil {
		return err
	}
	if info.Size() != expectedSize {
		return fmt.Errorf("uploaded file size does not match, actual: %v, expected: %v", info.Size(), expectedSize)
	}
	return nil
}

func uploadFileWithRawClient(localSourcePath string, remoteDestPath string, username, password string,
	useTLS bool, expectedSize int64, client *gowebdav.Client, headers ...dataprovider.KeyValue,
) error {
	srcFile, err := os.Open(localSourcePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	var tlsConfig *tls.Config
	rootPath := fmt.Sprintf("http://%v/", webDavServerAddr)
	if useTLS {
		rootPath = fmt.Sprintf("https://%v/", webDavTLSServerAddr)
		tlsConfig = &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, // use this for tests only
			MinVersion:         tls.VersionTLS12,
		}
	}
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%v%v", rootPath, remoteDestPath), srcFile)
	if err != nil {
		return err
	}
	req.SetBasicAuth(username, password)
	for _, kv := range headers {
		req.Header.Set(kv.Key, kv.Value)
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if tlsConfig != nil {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = tlsConfig
		httpClient.Transport = customTransport
	}
	defer httpClient.CloseIdleConnections()
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code: %v", resp.StatusCode)
	}
	if expectedSize > 0 {
		return checkFileSize(remoteDestPath, expectedSize, client)
	}
	return nil
}

// This method is buggy. I have to find time to better investigate and eventually report the issue upstream.
// For now we upload using the uploadFileWithRawClient method
/*func uploadFile(localSourcePath string, remoteDestPath string, expectedSize int64, client *gowebdav.Client) error {
	srcFile, err := os.Open(localSourcePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	err = client.WriteStream(remoteDestPath, srcFile, os.ModePerm)
	if err != nil {
		return err
	}
	if expectedSize > 0 {
		return checkFileSize(remoteDestPath, expectedSize, client)
	}
	return nil
}*/

func downloadFile(remoteSourcePath string, localDestPath string, expectedSize int64, client *gowebdav.Client) error {
	downloadDest, err := os.Create(localDestPath)
	if err != nil {
		return err
	}
	defer downloadDest.Close()

	reader, err := client.ReadStream(remoteSourcePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	written, err := io.Copy(downloadDest, reader)
	if err != nil {
		return err
	}
	if written != expectedSize {
		return fmt.Errorf("downloaded file size does not match, actual: %v, expected: %v", written, expectedSize)
	}
	return nil
}

func getTLSHTTPClient(tlsConfig *tls.Config) *http.Client {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = tlsConfig

	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: customTransport,
	}
}

func getWebDavClient(user dataprovider.User, useTLS bool, tlsConfig *tls.Config) *gowebdav.Client {
	rootPath := fmt.Sprintf("http://%v/", webDavServerAddr)
	if useTLS {
		rootPath = fmt.Sprintf("https://%v/", webDavTLSServerAddr)
		if tlsConfig == nil {
			tlsConfig = &tls.Config{
				ServerName:         "localhost",
				InsecureSkipVerify: true, // use this for tests only
				MinVersion:         tls.VersionTLS12,
			}
		}
	}
	pwd := defaultPassword
	if user.Password != "" {
		if user.Password == emptyPwdPlaceholder {
			pwd = ""
		} else {
			pwd = user.Password
		}
	}
	client := gowebdav.NewClient(rootPath, user.Username, pwd)
	client.SetTimeout(10 * time.Second)
	if tlsConfig != nil {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = tlsConfig
		client.SetTransport(customTransport)
	}
	return client
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

func getTestUserWithCryptFs() dataprovider.User {
	user := getTestUser()
	user.FsConfig.Provider = sdk.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("testPassphrase")
	return user
}

func getEncryptedFileSize(size int64) (int64, error) {
	encSize, err := sio.EncryptedSize(uint64(size))
	return int64(encSize) + 33, err
}

func getExtAuthScriptContent(user dataprovider.User, password string) []byte {
	extAuthContent := []byte("#!/bin/sh\n\n")
	if password != "" {
		extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("if test \"$SFTPGO_AUTHD_USERNAME\" = \"%s\" -a \"$SFTPGO_AUTHD_PASSWORD\" = \"%s\"; then\n", user.Username, password))...)
	} else {
		extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("if test \"$SFTPGO_AUTHD_USERNAME\" = \"%s\"; then\n", user.Username))...)
	}
	u, _ := json.Marshal(user)
	extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("echo '%s'\n", string(u)))...)
	extAuthContent = append(extAuthContent, []byte("else\n")...)
	extAuthContent = append(extAuthContent, []byte("echo '{\"username\":\"\"}'\n")...)
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
	if _, err := os.Stat(baseDir); errors.Is(err, fs.ErrNotExist) {
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

	err = os.WriteFile(path, content, os.ModePerm)
	if err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Size() != size {
		return fmt.Errorf("unexpected size %v, expected %v", fi.Size(), size)
	}
	return nil
}

func printLatestLogs(maxNumberOfLines int) {
	var lines []string
	f, err := os.Open(logFilePath)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text()+"\r\n")
		for len(lines) > maxNumberOfLines {
			lines = lines[1:]
		}
	}
	if scanner.Err() != nil {
		logger.WarnToConsole("Unable to print latest logs: %v", scanner.Err())
		return
	}
	for _, line := range lines {
		logger.DebugToConsole(line)
	}
}
