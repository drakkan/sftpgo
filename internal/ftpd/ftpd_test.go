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

package ftpd_test

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/ftpd"
	"github.com/drakkan/sftpgo/v2/internal/httpdtest"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	logSender               = "ftpdTesting"
	ftpServerAddr           = "127.0.0.1:2121"
	sftpServerAddr          = "127.0.0.1:2122"
	ftpSrvAddrTLS           = "127.0.0.1:2124" // ftp server with implicit tls
	ftpSrvAddrTLSResumption = "127.0.0.1:2126" // ftp server with implicit tls
	defaultUsername         = "test_user_ftp"
	defaultPassword         = "test_password"
	osWindows               = "windows"
	ftpsCert                = `-----BEGIN CERTIFICATE-----
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
	testFileName          = "test_file_ftp.dat"
	testDLFileName        = "test_download_ftp.dat"
	tlsClient1Username    = "client1"
	tlsClient2Username    = "client2"
	httpFsPort            = 23456
	defaultHTTPFsUsername = "httpfs_ftp_user"
	emptyPwdPlaceholder   = "empty"
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
	caCrtPath       string
	caCRLPath       string
)

func TestMain(m *testing.M) { //nolint:gocyclo
	logFilePath = filepath.Join(configDir, "sftpgo_ftpd_test.log")
	bannerFileName := "banner_file"
	bannerFile := filepath.Join(configDir, bannerFileName)
	logger.InitLogger(logFilePath, 5, 1, 28, false, false, zerolog.DebugLevel)
	err := os.WriteFile(bannerFile, []byte("SFTPGo test ready\nsimple banner line\n"), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error creating banner file: %v", err)
		os.Exit(1)
	}
	// we run the test cases with UploadMode atomic and resume support. The non atomic code path
	// simply does not execute some code so if it works in atomic mode will
	// work in non atomic mode too
	os.Setenv("SFTPGO_COMMON__UPLOAD_MODE", "2")
	os.Setenv("SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN", "1")
	os.Setenv("SFTPGO_COMMON__ALLOW_SELF_CONNECTIONS", "1")
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
			Port:               2121,
			ClientAuthType:     2,
			CertificateFile:    certPath,
			CertificateKeyFile: keyPath,
		},
	}
	ftpdConf.PassivePortRange.Start = 0
	ftpdConf.PassivePortRange.End = 0
	ftpdConf.BannerFile = bannerFileName
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
		if err := httpdConf.Initialize(configDir, 0); err != nil {
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

	ftpdConf = config.GetFTPDConfig()
	ftpdConf.Bindings = []ftpd.Binding{
		{
			Port:               2126,
			CertificateFile:    certPath,
			CertificateKeyFile: keyPath,
			TLSMode:            1,
			TLSSessionReuse:    1,
			ClientAuthType:     2,
		},
	}
	ftpdConf.CACertificates = []string{caCrtPath}
	ftpdConf.CARevocationLists = []string{caCRLPath}

	go func() {
		logger.Debug(logSender, "", "initializing FTP server with config %+v", ftpdConf)
		if err := ftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start FTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(ftpdConf.Bindings[0].GetAddress())

	waitNoConnections()
	startHTTPFs()

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
	ftpdConf.Bindings[1].TLSMode = 2
	ftpdConf.Bindings[1].TLSSessionReuse = 1
	err = ftpdConf.Initialize(configDir)
	require.Error(t, err, "TLS session resumption should not be supported with implicit FTPS")
	ftpdConf.Bindings[1].TLSMode = 0
	ftpdConf.Bindings[1].TLSSessionReuse = 100
	err = ftpdConf.Initialize(configDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported TLS reuse mode")
	ftpdConf.Bindings[1].TLSSessionReuse = 0
	err = ftpdConf.Initialize(configDir)
	require.Error(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = ftpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to load config from provider")
	}
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
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
				assert.Len(t, common.Connections.GetStats(""), 1)
			} else {
				assert.Len(t, common.Connections.GetStats(""), 2)
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
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, int64(0), user.FirstUpload)
			assert.Equal(t, int64(0), user.FirstDownload)
			err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Greater(t, user.FirstUpload, int64(0))
			assert.Equal(t, int64(0), user.FirstDownload)
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
			assert.Greater(t, user.FirstUpload, int64(0))
			assert.Greater(t, user.FirstDownload, int64(0))
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
			assert.Len(t, res, 0)
			res, err = client.List(path.Join("/"))
			assert.NoError(t, err)
			if assert.Len(t, res, 1) {
				assert.Equal(t, testDir, res[0].Name)
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
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 }, 1*time.Second, 50*time.Millisecond)
	assert.Eventually(t, func() bool { return common.Connections.GetClientConnections() == 0 }, 1000*time.Millisecond,
		50*time.Millisecond)
}

func TestHTTPFs(t *testing.T) {
	u := getTestUserWithHTTPFs()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		// test a download resume
		data := []byte("test data")
		err = os.WriteFile(testFilePath, data, os.ModePerm)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, testFileName, int64(len(data)), client, 0)
		assert.NoError(t, err)
		err = ftpDownloadFile(testFileName, localDownloadPath, int64(len(data)-5), client, 5)
		assert.NoError(t, err)
		readed, err := os.ReadFile(localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, []byte("data"), readed, "readed data mismatch: %q", string(readed))
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 }, 1*time.Second, 50*time.Millisecond)
	assert.Eventually(t, func() bool { return common.Connections.GetClientConnections() == 0 }, 1000*time.Millisecond,
		50*time.Millisecond)
}

func TestListDirWithWildcards(t *testing.T) {
	localUser, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(), http.StatusCreated)
	assert.NoError(t, err)

	defer func() {
		_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
		assert.NoError(t, err)
		_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(localUser.GetHomeDir())
		assert.NoError(t, err)
	}()

	for _, user := range []dataprovider.User{localUser, sftpUser} {
		client, err := getFTPClient(user, true, nil, ftp.DialWithDisabledMLSD(true))
		if assert.NoError(t, err) {
			dir1 := "test.dir"
			dir2 := "test.dir1"
			err = client.MakeDir(dir1)
			assert.NoError(t, err)
			err = client.MakeDir(dir2)
			assert.NoError(t, err)
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(65535)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			fileName := "file[a-z]e.dat"
			err = ftpUploadFile(testFilePath, fileName, testFileSize, client, 0)
			assert.NoError(t, err)
			localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
			err = ftpDownloadFile(fileName, localDownloadPath, testFileSize, client, 0)
			assert.NoError(t, err)
			entries, err := client.List(fileName)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Equal(t, fileName, entries[0].Name)
			nListEntries, err := client.NameList(fileName)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Contains(t, nListEntries, fileName)
			entries, err = client.List(".")
			require.NoError(t, err)
			require.Len(t, entries, 3)
			nListEntries, err = client.NameList(".")
			require.NoError(t, err)
			require.Len(t, nListEntries, 3)
			entries, err = client.List("/test.*")
			require.NoError(t, err)
			require.Len(t, entries, 2)
			found := 0
			for _, e := range entries {
				switch e.Name {
				case dir1, dir2:
					found++
				}
			}
			assert.Equal(t, 2, found)
			nListEntries, err = client.NameList("/test.*")
			require.NoError(t, err)
			require.Len(t, entries, 2)
			assert.Contains(t, nListEntries, dir1)
			assert.Contains(t, nListEntries, dir2)
			entries, err = client.List("/*.dir?")
			require.NoError(t, err)
			assert.Len(t, entries, 1)
			assert.Equal(t, dir2, entries[0].Name)
			nListEntries, err = client.NameList("/*.dir?")
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Contains(t, nListEntries, dir2)
			entries, err = client.List("/test.???")
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Equal(t, dir1, entries[0].Name)
			nListEntries, err = client.NameList("/test.???")
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Contains(t, nListEntries, dir1)
			_, err = client.NameList("/missingdir/test.*")
			assert.Error(t, err)
			_, err = client.List("/missingdir/test.*")
			assert.Error(t, err)
			_, err = client.NameList("test[-]")
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), path.ErrBadPattern.Error())
			}
			_, err = client.List("test[-]")
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), path.ErrBadPattern.Error())
			}
			subDir := path.Join(dir1, "sub.d")
			err = client.MakeDir(subDir)
			assert.NoError(t, err)
			err = client.ChangeDir(path.Dir(subDir))
			assert.NoError(t, err)
			entries, err = client.List("sub.?")
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Contains(t, path.Base(subDir), entries[0].Name)
			nListEntries, err = client.NameList("sub.?")
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Contains(t, nListEntries, path.Base(subDir))
			entries, err = client.List("../*.dir?")
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Equal(t, path.Join("../", dir2), entries[0].Name)
			nListEntries, err = client.NameList("../*.dir?")
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Contains(t, nListEntries, path.Join("../", dir2))

			err = client.ChangeDir("/")
			assert.NoError(t, err)
			entries, err = client.List(path.Join(dir1, "sub.*"))
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Equal(t, path.Join(dir1, "sub.d"), entries[0].Name)
			nListEntries, err = client.NameList(path.Join(dir1, "sub.*"))
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Contains(t, nListEntries, path.Join(dir1, "sub.d"))
			err = client.RemoveDir(subDir)
			assert.NoError(t, err)
			err = client.RemoveDir(dir1)
			assert.NoError(t, err)
			err = client.RemoveDir(dir2)
			assert.NoError(t, err)
			err = os.Remove(testFilePath)
			assert.NoError(t, err)
			err = os.Remove(localDownloadPath)
			assert.NoError(t, err)
			err = client.Quit()
			assert.NoError(t, err)
		}
	}
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
			if assert.Len(t, entries, 1) {
				assert.Equal(t, testFileName, entries[0].Name)
			}
			entries, err = client.List("/")
			assert.NoError(t, err)
			if assert.Len(t, entries, 1) {
				assert.Equal(t, "start", entries[0].Name)
			}
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

func TestLoginEmptyPassword(t *testing.T) {
	u := getTestUser()
	u.Password = ""
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	user.Password = emptyPwdPlaceholder

	_, err = getFTPClient(user, true, nil)
	assert.Error(t, err)

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
	assert.True(t, user.Filters.IsAnonymous)
	assert.Equal(t, []string{dataprovider.PermListItems, dataprovider.PermDownload}, user.Permissions["/"])
	assert.Equal(t, []string{common.ProtocolSSH, common.ProtocolHTTP}, user.Filters.DeniedProtocols)
	assert.Equal(t, []string{dataprovider.SSHLoginMethodPublicKey, dataprovider.SSHLoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive, dataprovider.SSHLoginMethodKeyAndPassword,
		dataprovider.SSHLoginMethodKeyAndKeyboardInt, dataprovider.LoginMethodTLSCertificate,
		dataprovider.LoginMethodTLSCertificateAndPwd}, user.Filters.DeniedLoginMethods)

	user.Password = emptyPwdPlaceholder
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)

		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)

		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "permission")
		}
		err = os.Rename(testFilePath, filepath.Join(user.GetHomeDir(), testFileName))
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err = client.MakeDir("adir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "permission")
		}

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

func TestAnonymousGroupInheritance(t *testing.T) {
	g := getTestGroup()
	g.UserSettings.Filters.IsAnonymous = true
	g.UserSettings.Permissions = make(map[string][]string)
	g.UserSettings.Permissions["/"] = allPerms
	g.UserSettings.Permissions["/testsub"] = allPerms
	group, _, err := httpdtest.AddGroup(g, http.StatusCreated)
	assert.NoError(t, err)
	u := getTestUser()
	u.Groups = []sdk.GroupMapping{
		{
			Name: group.Name,
			Type: sdk.GroupTypePrimary,
		},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	user.Password = emptyPwdPlaceholder
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)

		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)

		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "permission")
		}
		err = client.MakeDir("adir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "permission")
		}
		err = client.MakeDir("/testsub/adir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "permission")
		}
		err = os.Rename(testFilePath, filepath.Join(user.GetHomeDir(), testFileName))
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)

		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	user.Password = defaultPassword
	client, err = getFTPClient(user, true, nil)
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
	_, err = httpdtest.RemoveGroup(group, http.StatusOK)
	assert.NoError(t, err)
}

func TestMultiFactorAuth(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	configName, key, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(key.Secret()),
		Protocols:  []string{common.ProtocolFTP},
	}
	err = dataprovider.UpdateUser(&user, "", "", "")
	assert.NoError(t, err)

	user.Password = defaultPassword
	_, err = getFTPClient(user, true, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), dataprovider.ErrInvalidCredentials.Error())
	}
	passcode, err := generateTOTPPasscode(key.Secret(), otp.AlgorithmSHA1)
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

func TestMustChangePasswordRequirement(t *testing.T) {
	u := getTestUser()
	u.Filters.RequirePasswordChange = true
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	_, err = getFTPClient(user, true, nil)
	assert.Error(t, err)

	err = dataprovider.UpdateUserPassword(user.Username, defaultPassword, "", "", "")
	assert.NoError(t, err)

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

func TestSecondFactorRequirement(t *testing.T) {
	u := getTestUser()
	u.Filters.TwoFactorAuthProtocols = []string{common.ProtocolFTP}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	_, err = getFTPClient(user, true, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "second factor authentication is not set")
	}

	configName, key, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(key.Secret()),
		Protocols:  []string{common.ProtocolFTP},
	}
	err = dataprovider.UpdateUser(&user, "", "", "")
	assert.NoError(t, err)
	passcode, err := generateTOTPPasscode(key.Secret(), otp.AlgorithmSHA1)
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

func TestFTPSecurity(t *testing.T) {
	u := getTestUser()
	u.Filters.FTPSecurity = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}
	_, err = getFTPClient(user, false, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "TLS is required")
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestGroupFTPSecurity(t *testing.T) {
	g := getTestGroup()
	g.UserSettings.Filters.FTPSecurity = 1
	group, _, err := httpdtest.AddGroup(g, http.StatusCreated)
	assert.NoError(t, err)
	u := getTestUser()
	u.Groups = []sdk.GroupMapping{
		{
			Name: group.Name,
			Type: sdk.GroupTypePrimary,
		},
	}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}
	_, err = getFTPClient(user, false, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "TLS is required")
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveGroup(group, http.StatusOK)
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
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	g := getTestGroup()
	g.UserSettings.Filters.DeniedProtocols = []string{common.ProtocolFTP}
	group, _, err := httpdtest.AddGroup(g, http.StatusCreated)
	assert.NoError(t, err)

	client, err := getFTPClient(u, true, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
	}
	u.Groups = []sdk.GroupMapping{
		{
			Name: group.Name,
			Type: sdk.GroupTypePrimary,
		},
	}
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u), os.ModePerm)
	assert.NoError(t, err)
	_, err = getFTPClient(u, true, nil)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	} else {
		assert.Contains(t, err.Error(), "protocol FTP is not allowed")
	}

	u.Groups = nil
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u), os.ModePerm)
	assert.NoError(t, err)
	u.Username = defaultUsername + "1"
	client, err = getFTPClient(u, true, nil)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	} else {
		assert.Contains(t, err.Error(), "invalid credentials")
	}

	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, defaultUsername, user.Username)
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
	user.Status = 0
	user.Filters.FTPSecurity = 1
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(user, false), os.ModePerm)
	assert.NoError(t, err)
	client, err = getFTPClient(u, true, nil)
	if !assert.Error(t, err) {
		err := client.Quit()
		assert.NoError(t, err)
	}
	_, err = getFTPClient(user, false, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "TLS is required")
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

func TestPreLoginHookReturningAnonymousUser(t *testing.T) {
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
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(u, false), os.ModePerm)
	assert.NoError(t, err)
	providerConf.PreLoginHook = preLoginPath
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	// the pre-login hook create the anonymous user
	client, err := getFTPClient(u, false, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)

		err = client.MakeDir("tdiranonymous")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "permission")
		}
		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "permission")
		}
		err = os.Rename(testFilePath, filepath.Join(u.GetHomeDir(), testFileName))
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
		err := client.Quit()
		assert.NoError(t, err)
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
	// now the same with an existing user
	client, err = getFTPClient(u, false, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)

		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "permission")
		}
		err = os.Rename(testFilePath, filepath.Join(u.GetHomeDir(), testFileName))
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)
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
	err := dataprovider.AddUser(&user, "", "", "")
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
	err = dataprovider.DeleteUser(user.Username, "", "", "")
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
	err := dataprovider.AddUser(&user, "", "", "")
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
	err = dataprovider.DeleteUser(user.Username, "", "", "")
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

	err = dataprovider.DeleteUser(user.Username, "", "", "")
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
	cfg.DefenderConfig.Threshold = 4
	cfg.DefenderConfig.ScoreLimitExceeded = 2
	cfg.DefenderConfig.ScoreNoAuth = 1
	cfg.DefenderConfig.ScoreValid = 1

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
	// just dial without login
	ftpOptions := []ftp.DialOption{ftp.DialWithTimeout(5 * time.Second)}
	client, err = ftp.Dial(ftpServerAddr, ftpOptions...)
	assert.NoError(t, err)
	err = client.Quit()
	assert.NoError(t, err)
	hosts, _, err := httpdtest.GetDefenderHosts(http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, hosts, 1) {
		host := hosts[0]
		assert.Empty(t, host.GetBanTime())
		assert.Equal(t, 1, host.Score)
	}
	user.Password = "wrong_pwd"
	_, err = getFTPClient(user, false, nil)
	assert.Error(t, err)
	hosts, _, err = httpdtest.GetDefenderHosts(http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, hosts, 1) {
		host := hosts[0]
		assert.Empty(t, host.GetBanTime())
		assert.Equal(t, 2, host.Score)
	}

	for i := 0; i < 2; i++ {
		_, err = getFTPClient(user, false, nil)
		assert.Error(t, err)
	}

	user.Password = defaultPassword
	_, err = getFTPClient(user, false, nil)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "banned client IP")
	}

	err = dataprovider.DeleteUser(user.Username, "", "", "")
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
	u = getTestUser()
	u.FsConfig.OSConfig = sdk.OSFsConfig{
		ReadBufferSize:  1,
		WriteBufferSize: 1,
	}
	u.Username += "_buf"
	u.HomeDir += "_buf"
	bufferedUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser, bufferedUser} {
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
			// append to a new file
			srcFile, err = os.Open(testFilePath)
			if assert.NoError(t, err) {
				newFileName := testFileName + "_new"
				err = client.Append(newFileName, srcFile)
				assert.NoError(t, err)
				err = srcFile.Close()
				assert.NoError(t, err)
				size, err := client.FileSize(newFileName)
				assert.NoError(t, err)
				assert.Equal(t, int64(len(data)), size)
				err = ftpDownloadFile(newFileName, localDownloadPath, int64(len(data)), client, 0)
				assert.NoError(t, err)
				readed, err = os.ReadFile(localDownloadPath)
				assert.NoError(t, err)
				assert.Equal(t, data, readed)
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
	_, err = httpdtest.RemoveUser(bufferedUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(bufferedUser.GetHomeDir())
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
			err = ftpUploadFile(testFilePath, testFileName+".quota", testFileSize, client, 0) //nolint:goconst
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
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.GCSConfig.Credentials.GetStatus())
	assert.NotEmpty(t, user.FsConfig.GCSConfig.Credentials.GetPayload())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetAdditionalData())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetKey())

	client, err := getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		err = client.Quit()
		assert.NoError(t, err)
	}

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

	client, err := getFTPClient(user, false, nil)
	if !assert.Error(t, err) {
		err = client.Quit()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
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
		stats := common.Connections.GetStats("")
		if assert.Len(t, stats, 1) {
			common.Connections.Close(stats[0].ConnectionID, "")
			assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 },
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
				code, response, err := client.SendCommand(fmt.Sprintf("SITE CHMOD 0001 %v", otherDir))
				assert.NoError(t, err)
				assert.Equal(t, ftp.StatusCommandOK, code)
				assert.Equal(t, "SITE CHMOD command successful", response)
				err = client.Rename(testDir, path.Join(otherDir, testDir))
				assert.Error(t, err)

				code, response, err = client.SendCommand(fmt.Sprintf("SITE CHMOD 755 %v", otherDir))
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
			code, _, err := client.SendCommand(fmt.Sprintf("SITE SYMLINK %v %v", testFileName, testFileName+".link"))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusCommandOK, code)

			if runtime.GOOS != osWindows {
				testDir := "adir"
				otherDir := "dir"
				err = client.MakeDir(otherDir)
				assert.NoError(t, err)
				err = client.MakeDir(path.Join(otherDir, testDir))
				assert.NoError(t, err)
				code, response, err := client.SendCommand(fmt.Sprintf("SITE CHMOD 0001 %v", otherDir))
				assert.NoError(t, err)
				assert.Equal(t, ftp.StatusCommandOK, code)
				assert.Equal(t, "SITE CHMOD command successful", response)
				code, _, err = client.SendCommand(fmt.Sprintf("SITE SYMLINK %v %v", testDir, path.Join(otherDir, testDir)))
				assert.NoError(t, err)
				assert.Equal(t, ftp.StatusFileUnavailable, code)

				code, response, err = client.SendCommand(fmt.Sprintf("SITE CHMOD 755 %v", otherDir))
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
		VirtualPath: "/vdir",
		QuotaSize:   110,
	})
	err = os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCommand("allo 2000000")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)

		code, response, err = client.SendCommand("AVBL /vdir")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusFile, code)
		assert.Equal(t, "110", response)

		code, _, err = client.SendCommand("AVBL")
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
		code, response, err := client.SendCommand("allo 1000")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)

		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)

		code, response, err = client.SendCommand("AVBL")
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
		code, response, err := client.SendCommand("AVBL")
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
		code, response, err := client.SendCommand("AVBL")
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
		code, response, err := client.SendCommand("AVBL")
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
		code, response, err := client.SendCommand("allo 10000")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusCommandOK, code)
		assert.Equal(t, "Done !", response)

		code, response, err = client.SendCommand("AVBL")
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
		code, response, err := client.SendCommand("AVBL")
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
		code, response, err := client.SendCommand("AVBL")
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
		code, response, err := client.SendCommand("AVBL /")
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
			code, response, err := client.SendCommand(fmt.Sprintf("MFMT %v %v", mtime, testFileName))
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

func TestSTAT(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	assert.NoError(t, err)
	client, err := getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(131072)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		testDir := "testdir"
		err = client.MakeDir(testDir)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join(testDir, testFileName), testFileSize, client, 0)
		assert.NoError(t, err)
		err = ftpUploadFile(testFilePath, path.Join(testDir, testFileName+"_1"), testFileSize, client, 0)
		assert.NoError(t, err)
		code, response, err := client.SendCommand(fmt.Sprintf("STAT %s", testDir))
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusDirectory, code)
		assert.Contains(t, response, fmt.Sprintf("STAT %s", testDir))
		assert.Contains(t, response, testFileName)
		assert.Contains(t, response, testFileName+"_1")
		assert.Contains(t, response, "End")

		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
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
		code, response, err := client.SendCommand(fmt.Sprintf("SITE CHOWN 1000:1000 %v", testFileName))
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

			code, response, err := client.SendCommand(fmt.Sprintf("SITE CHMOD 600 %v", testFileName))
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

			code, response, err := client.SendCommand("COMB file file.1 file.2")
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
		code, response, err := client.SendCommand("PORT 10,2,0,2,4,31")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusNotAvailable, code)
		assert.Equal(t, "PORT command is disabled", response)

		code, response, err = client.SendCommand("EPRT |1|132.235.1.2|6275|")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusNotAvailable, code)
		assert.Equal(t, "EPRT command is disabled", response)

		err = client.Quit()
		assert.NoError(t, err)
	}

	client, err = getFTPClient(user, false, nil)
	if assert.NoError(t, err) {
		code, response, err := client.SendCommand("PORT 10,2,0,2,4,31")
		assert.NoError(t, err)
		assert.Equal(t, ftp.StatusBadArguments, code)
		assert.Equal(t, "Your request does not meet the configured security requirements", response)

		code, response, err = client.SendCommand("EPRT |1|132.235.1.2|6275|")
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

		code, response, err := client.SendCommand("SITE CHMOD 600 afile.txt")
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

			code, response, err := client.SendCommand(fmt.Sprintf("XSHA256 %v", testFileName))
			assert.NoError(t, err)
			assert.Equal(t, ftp.StatusRequestedFileActionOK, code)
			assert.Contains(t, response, hash)

			code, response, err = client.SendCommand(fmt.Sprintf("HASH %v", testFileName))
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

			code, response, err := client.SendCommand(fmt.Sprintf("COMB %v %v %v", testFileName, testFileName+".1", testFileName+".2"))
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

func TestTLSSessionReuse(t *testing.T) {
	u := getTestUser()
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	client, err := getFTPClientWithSessionReuse(user, nil)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)

		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)

		err = ftpUploadFile(testFilePath, testFileName, testFileSize, client, 0)
		assert.NoError(t, err)

		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = ftpDownloadFile(testFileName, localDownloadPath, testFileSize, client, 0)
		assert.NoError(t, err)

		entries, err := client.List("/")
		assert.NoError(t, err)
		assert.Len(t, entries, 1)

		err = client.Quit()
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}

	// this TLS config does not support session resumption
	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // use this for tests only
		MinVersion:         tls.VersionTLS12,
	}
	client, err = getFTPClientWithSessionReuse(user, tlsConfig)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.Error(t, err)

		err = client.Quit()
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
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
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}
	tlsCert, err := tls.X509KeyPair([]byte(client2Crt), []byte(client2Key))
	assert.NoError(t, err)
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
	_, err = getFTPClientWithSessionReuse(user, tlsConfig)
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
	// add the certs to the user
	user2.Filters.TLSUsername = sdk.TLSUsernameNone
	user2.Filters.TLSCerts = []string{client2Crt, client1Crt}
	user2, _, err = httpdtest.UpdateUser(user2, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getFTPClient(user2, true, tlsConfig)
	if assert.NoError(t, err) {
		err = checkBasicFTP(client)
		assert.NoError(t, err)
		err = client.Quit()
		assert.NoError(t, err)
	}
	user2.Filters.TLSCerts = []string{client2Crt}
	user2, _, err = httpdtest.UpdateUser(user2, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = getFTPClient(user2, true, tlsConfig)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "TLS certificate is not valid")
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

func TestExternalAuthWithClientCert(t *testing.T) {
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
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u), os.ModePerm)
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
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats("")) == 0 }, 1*time.Second, 50*time.Millisecond)
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

func getFTPClientWithSessionReuse(user dataprovider.User, tlsConfig *tls.Config, dialOptions ...ftp.DialOption,
) (*ftp.ServerConn, error) {
	ftpOptions := []ftp.DialOption{ftp.DialWithTimeout(5 * time.Second)}
	ftpOptions = append(ftpOptions, dialOptions...)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, // use this for tests only
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
		}
	}
	ftpOptions = append(ftpOptions, ftp.DialWithExplicitTLS(tlsConfig))
	client, err := ftp.Dial(ftpSrvAddrTLSResumption, ftpOptions...)
	if err != nil {
		return nil, err
	}
	pwd := defaultPassword
	if user.Password != "" {
		if user.Password == emptyPwdPlaceholder {
			pwd = ""
		} else {
			pwd = user.Password
		}
	}
	err = client.Login(user.Username, pwd)
	if err != nil {
		return nil, err
	}
	return client, err
}

func getFTPClient(user dataprovider.User, useTLS bool, tlsConfig *tls.Config, dialOptions ...ftp.DialOption,
) (*ftp.ServerConn, error) {
	ftpOptions := []ftp.DialOption{ftp.DialWithTimeout(5 * time.Second)}
	ftpOptions = append(ftpOptions, dialOptions...)
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
		if user.Password == emptyPwdPlaceholder {
			pwd = ""
		} else {
			pwd = user.Password
		}
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
	for len(common.Connections.GetStats("")) > 0 {
		time.Sleep(50 * time.Millisecond)
	}
}

func getTestGroup() dataprovider.Group {
	return dataprovider.Group{
		BaseGroup: sdk.BaseGroup{
			Name:        "test_group",
			Description: "test group description",
		},
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

func getTestUserWithHTTPFs() dataprovider.User {
	u := getTestUser()
	u.FsConfig.Provider = sdk.HTTPFilesystemProvider
	u.FsConfig.HTTPConfig = vfs.HTTPFsConfig{
		BaseHTTPFsConfig: sdk.BaseHTTPFsConfig{
			Endpoint: fmt.Sprintf("http://127.0.0.1:%d/api/v1", httpFsPort),
			Username: defaultHTTPFsUsername,
		},
	}
	return u
}

func getExtAuthScriptContent(user dataprovider.User) []byte {
	extAuthContent := []byte("#!/bin/sh\n\n")
	extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("if test \"$SFTPGO_AUTHD_USERNAME\" = \"%v\"; then\n", user.Username))...)
	u, _ := json.Marshal(user)
	extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("echo '%v'\n", string(u)))...)
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

func startHTTPFs() {
	go func() {
		if err := httpdtest.StartTestHTTPFs(httpFsPort, nil); err != nil {
			logger.ErrorToConsole("could not start HTTPfs test server: %v", err)
			os.Exit(1)
		}
	}()
	waitTCPListening(fmt.Sprintf(":%d", httpFsPort))
}
