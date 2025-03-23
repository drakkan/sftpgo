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

package httpd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/klauspost/compress/zip"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	sdkkms "github.com/sftpgo/sdk/kms"
	"github.com/sftpgo/sdk/plugin/notifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"

	"github.com/drakkan/sftpgo/v2/internal/acme"
	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	httpdCert = `-----BEGIN CERTIFICATE-----
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
	httpdKey = `-----BEGIN EC PARAMETERS-----
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
MIIJKgIBAAKCAgEA7WHW216mfi4uF8cx6HWf8wvAxaEWgCHTOi2MwFIzOrOtuT7x
b64rkpdzx1aWetSiCrEyc3D1v03k0Akvlz1gtnDtO64+MA8bqlTnCydZJY4cCTvD
OBUYZgtMqHZzpE6xRrqQ84zhyzjKQ5bR0st+XGfIkuhjSuf2n/ZPS37fge9j6AKz
n/2uEVt33qmO85WtN3RzbSqLCdOJ6cQ216j3la1C5+NWvzIKC7t6NE1bBGI4+tRj
7B5P5MeamkkogwbExUjdHp3U4yasvoGcCHUQDoa4Dej1faywz6JlwB6rTV4ys4aZ
De67V/Q8iB2May1k7zBz1ZtbKF5Em3xewP1LqPEowF1uc4KtPGcP4bxdaIpSpmOb
cn8AIfH6smLQrn0C3cs7CYfoNlFuTbwzENUhjz0X6EsoM4w4c87lO+dRNR7YpHLq
R/BJTbbyXUB0imne1u00fuzbS7OtweiA9w7DRCkr2gU4lmHe7l0T+SA9pxIeVLb7
8x7ivdyXSF5LVQJ1JvhhWu6iM6GQdLHat/0fpRFUbEe34RQSDJ2eOBifMJqvsvpB
P8d2jcRZVUVrSXGc2mAGuGOY/tmnCJGW8Fd+sgpCVAqM0pxCM+apqrvJYUqqQZ2Z
xugCXULtRWJ9p4C9zUl40HEyOQ+AaiiwFll/doXELglcJdNg8AZPGhugfxMCAwEA
AQKCAgEA4x0OoceG54ZrVxifqVaQd8qw3uRmUKUMIMdfuMlsdideeLO97ynmSlRY
00kGo/I4Lp6mNEjI9gUie9+uBrcUhri4YLcujHCH+YlNnCBDbGjwbe0ds9SLCWaa
KztZHMSlW5Q4Bqytgu+MpOnxSgqjlOk+vz9TcGFKVnUkHIkAcqKFJX8gOFxPZA/t
Ob1kJaz4kuv5W2Kur/ISKvQtvFvOtQeV0aJyZm8LqXnvS4cPI7yN4329NDU0HyDR
y/deqS2aqV4zII3FFqbz8zix/m1xtVQzWCugZGMKrz0iuJMfNeCABb8rRGc6GsZz
+465v/kobqgeyyneJ1s5rMFrLp2o+dwmnIVMNsFDUiN1lIZDHLvlgonaUO3IdTZc
9asamFWKFKUMgWqM4zB1vmUO12CKowLNIIKb0L+kf1ixaLLDRGf/f9vLtSHE+oyx
lATiS18VNA8+CGsHF6uXMRwf2auZdRI9+s6AAeyRISSbO1khyWKHo+bpOvmPAkDR
nknTjbYgkoZOV+mrsU5oxV8s6vMkuvA3rwFhT2gie8pokuACFcCRrZi9MVs4LmUQ
u0GYTHvp2WJUjMWBm6XX7Hk3g2HV842qpk/mdtTjNsXws81djtJPn4I/soIXSgXz
pY3SvKTuOckP9OZVF0yqKGeZXKpD288PKpC+MAg3GvEJaednagECggEBAPsfLwuP
L1kiDjXyMcRoKlrQ6Q/zBGyBmJbZ5uVGa02+XtYtDAzLoVupPESXL0E7+r8ZpZ39
0dV4CEJKpbVS/BBtTEkPpTK5kz778Ib04TAyj+YLhsZjsnuja3T5bIBZXFDeDVDM
0ZaoFoKpIjTu2aO6pzngsgXs6EYbo2MTuJD3h0nkGZsICL7xvT9Mw0P1p2Ftt/hN
+jKk3vN220wTWUsq43AePi45VwK+PNP12ZXv9HpWDxlPo3j0nXtgYXittYNAT92u
BZbFAzldEIX9WKKZgsWtIzLaASjVRntpxDCTby/nlzQ5dw3DHU1DV3PIqxZS2+Oe
KV+7XFWgZ44YjYECggEBAPH+VDu3QSrqSahkZLkgBtGRkiZPkZFXYvU6kL8qf5wO
Z/uXMeqHtznAupLea8I4YZLfQim/NfC0v1cAcFa9Ckt9g3GwTSirVcN0AC1iOyv3
/hMZCA1zIyIcuUplNr8qewoX71uPOvCNH0dix77423mKFkJmNwzy4Q+rV+qkRdLn
v+AAgh7g5N91pxNd6LQJjoyfi1Ka6rRP2yGXM5v7QOwD16eN4JmExUxX1YQ7uNuX
pVS+HRxnBquA+3/DB1LtBX6pa2cUa+LRUmE/NCPHMvJcyuNkYpJKlNTd9vnbfo0H
RNSJSWm+aGxDFMjuPjV3JLj2OdKMPwpnXdh2vBZCPpMCggEAM+yTvrEhmi2HgLIO
hkz/jP2rYyfdn04ArhhqPLgd0dpuI5z24+Jq/9fzZT9ZfwSW6VK1QwDLlXcXRhXH
Q8Hf6smev3CjuORURO61IkKaGWwrAucZPAY7ToNQ4cP9ImDXzMTNPgrLv3oMBYJR
V16X09nxX+9NABqnQG/QjdjzDc6Qw7+NZ9f2bvzvI5qMuY2eyW91XbtJ45ThoLfP
ymAp03gPxQwL0WT7z85kJ3OrROxzwaPvxU0JQSZbNbqNDPXmFTiECxNDhpRAAWlz
1DC5Vg2l05fkMkyPdtD6nOQWs/CYSfB5/EtxiX/xnBszhvZUIe6KFvuKFIhaJD5h
iykagQKCAQEAoBRm8k3KbTIo4ZzvyEq4V/+dF3zBRczx6FkCkYLygXBCNvsQiR2Y
BjtI8Ijz7bnQShEoOmeDriRTAqGGrspEuiVgQ1+l2wZkKHRe/aaij/Zv+4AuhH8q
uZEYvW7w5Uqbs9SbgQzhp2kjTNy6V8lVnjPLf8cQGZ+9Y9krwktC6T5m/i435WdN
38h7amNP4XEE/F86Eb3rDrZYtgLIoCF4E+iCyxMehU+AGH1uABhls9XAB6vvo+8/
SUp8lEqWWLP0U5KNOtYWfCeOAEiIHDbUq+DYUc4BKtbtV1cx3pzlPTOWw6XBi5Lq
jttdL4HyYvnasAQpwe8GcMJqIRyCVZMiwwKCAQEAhQTTS3CC8PwcoYrpBdTjW1ck
vVFeF1YbfqPZfYxASCOtdx6wRnnEJ+bjqntagns9e88muxj9UhxSL6q9XaXQBD8+
2AmKUxphCZQiYFZcTucjQEQEI2nN+nAKgRrUSMMGiR8Ekc2iFrcxBU0dnSohw+aB
PbMKVypQCREu9PcDFIp9rXQTeElbaNsIg1C1w/SQjODbmN/QFHTVbRODYqLeX1J/
VcGsykSIq7hv6bjn7JGkr2JTdANbjk9LnMjMdJFsKRYxPKkOQfYred6Hiojp5Sor
PW5am8ejnNSPhIfqQp3uV3KhwPDKIeIpzvrB4uPfTjQWhekHCb8cKSWux3flqw==
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
	defaultAdminUsername = "admin"
	defaultAdminPass     = "password"
	defeaultUsername     = "test_user"
)

var (
	configDir = filepath.Join(".", "..", "..")
)

type failingWriter struct {
}

func (r *failingWriter) Write(_ []byte) (n int, err error) {
	return 0, errors.New("write error")
}

func (r *failingWriter) WriteHeader(_ int) {}

func (r *failingWriter) Header() http.Header {
	return make(http.Header)
}

func TestShouldBind(t *testing.T) {
	c := Conf{
		Bindings: []Binding{
			{
				Port: 10000,
			},
		},
	}
	require.False(t, c.ShouldBind())
	c.Bindings[0].EnableRESTAPI = true
	require.True(t, c.ShouldBind())

	c.Bindings[0].Port = 0
	require.False(t, c.ShouldBind())

	if runtime.GOOS != osWindows {
		c.Bindings[0].Address = "/absolute/path"
		require.True(t, c.ShouldBind())
	}
}

func TestBrandingValidation(t *testing.T) {
	b := Binding{
		Branding: Branding{
			WebAdmin: UIBranding{
				LogoPath:   "path1",
				DefaultCSS: []string{"my.css"},
			},
			WebClient: UIBranding{
				FaviconPath:    "favicon1.ico",
				DisclaimerPath: "../path2",
				ExtraCSS:       []string{"1.css"},
			},
		},
	}
	b.checkBranding()
	assert.Equal(t, "/favicon.png", b.Branding.WebAdmin.FaviconPath)
	assert.Equal(t, "/path1", b.Branding.WebAdmin.LogoPath)
	assert.Equal(t, []string{"/my.css"}, b.Branding.WebAdmin.DefaultCSS)
	assert.Len(t, b.Branding.WebAdmin.ExtraCSS, 0)
	assert.Equal(t, "/favicon1.ico", b.Branding.WebClient.FaviconPath)
	assert.Equal(t, path.Join(webStaticFilesPath, "/path2"), b.Branding.WebClient.DisclaimerPath)
	if assert.Len(t, b.Branding.WebClient.ExtraCSS, 1) {
		assert.Equal(t, "/1.css", b.Branding.WebClient.ExtraCSS[0])
	}
	b.Branding.WebAdmin.DisclaimerPath = "https://example.com"
	b.checkBranding()
	assert.Equal(t, "https://example.com", b.Branding.WebAdmin.DisclaimerPath)
}

func TestRedactedConf(t *testing.T) {
	c := Conf{
		SigningPassphrase: "passphrase",
		Setup: SetupConfig{
			InstallationCode: "123",
		},
	}
	redactedField := "[redacted]"
	redactedConf := c.getRedacted()
	assert.Equal(t, redactedField, redactedConf.SigningPassphrase)
	assert.Equal(t, redactedField, redactedConf.Setup.InstallationCode)
	assert.NotEqual(t, c.SigningPassphrase, redactedConf.SigningPassphrase)
	assert.NotEqual(t, c.Setup.InstallationCode, redactedConf.Setup.InstallationCode)
}

func TestGetRespStatus(t *testing.T) {
	var err error
	err = util.NewMethodDisabledError("")
	respStatus := getRespStatus(err)
	assert.Equal(t, http.StatusForbidden, respStatus)
	err = fmt.Errorf("generic error")
	respStatus = getRespStatus(err)
	assert.Equal(t, http.StatusInternalServerError, respStatus)
	respStatus = getRespStatus(plugin.ErrNoSearcher)
	assert.Equal(t, http.StatusNotImplemented, respStatus)
}

func TestMappedStatusCode(t *testing.T) {
	err := os.ErrPermission
	code := getMappedStatusCode(err)
	assert.Equal(t, http.StatusForbidden, code)
	err = os.ErrNotExist
	code = getMappedStatusCode(err)
	assert.Equal(t, http.StatusNotFound, code)
	err = common.ErrQuotaExceeded
	code = getMappedStatusCode(err)
	assert.Equal(t, http.StatusRequestEntityTooLarge, code)
	err = os.ErrClosed
	code = getMappedStatusCode(err)
	assert.Equal(t, http.StatusInternalServerError, code)
	err = &http.MaxBytesError{}
	code = getMappedStatusCode(err)
	assert.Equal(t, http.StatusRequestEntityTooLarge, code)
}

func TestGCSWebInvalidFormFile(t *testing.T) {
	form := make(url.Values)
	form.Set("username", "test_username")
	form.Set("fs_provider", "2")
	req, _ := http.NewRequest(http.MethodPost, webUserPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err := req.ParseForm()
	assert.NoError(t, err)
	_, err = getFsConfigFromPostFields(req)
	assert.EqualError(t, err, http.ErrNotMultipart.Error())
}

func TestBrandingInvalidFormFile(t *testing.T) {
	form := make(url.Values)
	req, _ := http.NewRequest(http.MethodPost, webConfigsPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err := req.ParseForm()
	assert.NoError(t, err)
	_, err = getBrandingConfigFromPostFields(req, &dataprovider.BrandingConfigs{})
	assert.EqualError(t, err, http.ErrNotMultipart.Error())
}

func TestTokenDuration(t *testing.T) {
	assert.Equal(t, shareTokenDuration, getTokenDuration(tokenAudienceWebShare))
	assert.Equal(t, apiTokenDuration, getTokenDuration(tokenAudienceAPI))
	assert.Equal(t, apiTokenDuration, getTokenDuration(tokenAudienceAPIUser))
	assert.Equal(t, cookieTokenDuration, getTokenDuration(tokenAudienceWebAdmin))
	assert.Equal(t, csrfTokenDuration, getTokenDuration(tokenAudienceCSRF))
	assert.Equal(t, 20*time.Minute, getTokenDuration(""))

	updateTokensDuration(30, 660, 360)
	assert.Equal(t, 30*time.Minute, apiTokenDuration)
	assert.Equal(t, 11*time.Hour, cookieTokenDuration)
	assert.Equal(t, 11*time.Hour, csrfTokenDuration)
	assert.Equal(t, 6*time.Hour, shareTokenDuration)
	assert.Equal(t, 11*time.Hour, getMaxCookieDuration())

	csrfTokenDuration = 1 * time.Hour
	assert.Equal(t, 11*time.Hour, getMaxCookieDuration())
}

func TestVerifyCSRFToken(t *testing.T) {
	server := httpdServer{}
	server.initializeRouter()
	req, err := http.NewRequest(http.MethodPost, webAdminEventActionPath, nil)
	require.NoError(t, err)
	req = req.WithContext(context.WithValue(req.Context(), jwtauth.ErrorCtxKey, fs.ErrPermission))

	rr := httptest.NewRecorder()
	tokenString := createCSRFToken(rr, req, server.csrfTokenAuth, "", webBaseAdminPath)
	assert.NotEmpty(t, tokenString)

	token, err := server.csrfTokenAuth.Decode(tokenString)
	require.NoError(t, err)
	_, ok := token.Get(claimRef)
	assert.False(t, ok)

	req.Form = url.Values{}
	req.Form.Set(csrfFormToken, tokenString)
	err = verifyCSRFToken(req, server.csrfTokenAuth)
	assert.ErrorIs(t, err, fs.ErrPermission)

	req, err = http.NewRequest(http.MethodPost, webAdminEventActionPath, nil)
	require.NoError(t, err)
	req.Form = url.Values{}
	req.Form.Set(csrfFormToken, tokenString)
	err = verifyCSRFToken(req, server.csrfTokenAuth)
	assert.ErrorContains(t, err, "the form token is not valid")
}

func TestInvalidToken(t *testing.T) {
	server := httpdServer{}
	server.initializeRouter()
	admin := dataprovider.Admin{
		Username: "admin",
	}
	errFake := errors.New("fake error")
	asJSON, err := json.Marshal(admin)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPut, path.Join(adminPath, admin.Username), bytes.NewBuffer(asJSON))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("username", admin.Username)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), jwtauth.ErrorCtxKey, errFake))
	rr := httptest.NewRecorder()
	updateAdmin(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	rr = httptest.NewRecorder()
	deleteAdmin(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	adminPwd := pwdChange{
		CurrentPassword: "old",
		NewPassword:     "new",
	}
	asJSON, err = json.Marshal(adminPwd)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodPut, "", bytes.NewBuffer(asJSON))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), jwtauth.ErrorCtxKey, errFake))
	rr = httptest.NewRecorder()
	changeAdminPassword(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	adm := getAdminFromToken(req)
	assert.Empty(t, adm.Username)

	rr = httptest.NewRecorder()
	readUserFolder(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getUserFile(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getUserFilesAsZipStream(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getShares(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getShareByID(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	addShare(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateShare(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	deleteShare(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	generateTOTPSecret(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	saveTOTPConfig(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getRecoveryCodes(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	generateRecoveryCodes(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getUserProfile(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateUserProfile(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getWebTask(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getAdminProfile(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateAdminProfile(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	loadData(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	loadDataFromRequest(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	addUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	disableUser2FA(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	deleteUser(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getActiveConnections(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	handleCloseConnection(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebRestore(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebAddUserPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebUpdateUserPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebTemplateFolderPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebTemplateUserPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	getAllAdmins(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	getAllUsers(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	addFolder(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateFolder(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getFolderByName(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	deleteFolder(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebAddFolderPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebUpdateFolderPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebGetConnections(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebConfigsPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	addAdmin(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	disableAdmin2FA(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	addAPIKey(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateAPIKey(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	deleteAPIKey(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	addGroup(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateGroup(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getGroupByName(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	deleteGroup(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	addEventAction(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getEventActionByName(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateEventAction(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	deleteEventAction(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getEventRuleByName(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	addEventRule(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateEventRule(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	deleteEventRule(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getUsersQuotaScans(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateUserTransferQuotaUsage(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	doUpdateUserQuotaUsage(rr, req, "", quotaUsage{})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	doStartUserQuotaScan(rr, req, "")
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getRetentionChecks(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	addRole(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateRole(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	deleteRole(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getUsers(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	getUserByUsername(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	searchFsEvents(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	searchProviderEvents(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	searchLogEvents(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	addIPListEntry(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	updateIPListEntry(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	deleteIPListEntry(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	server.handleGetWebUsers(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebUpdateUserGet(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebUpdateRolePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebAddRolePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebAddAdminPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebAddGroupPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebUpdateGroupPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebAddEventActionPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebUpdateEventActionPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebAddEventRulePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebUpdateEventRulePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebUpdateIPListEntryPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	server.handleWebClientTwoFactorRecoveryPost(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	server.handleWebClientTwoFactorPost(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	server.handleWebAdminTwoFactorRecoveryPost(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	server.handleWebAdminTwoFactorPost(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	server.handleWebUpdateIPListEntryPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	form := make(url.Values)
	req, _ = http.NewRequest(http.MethodPost, webIPListPath+"/1", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("type", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr = httptest.NewRecorder()
	server.handleWebAddIPListEntryPost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)
}

func TestTokenSignatureValidation(t *testing.T) {
	tokenValidationMode = 0
	server := httpdServer{
		binding: Binding{
			Address:         "",
			Port:            8080,
			EnableWebAdmin:  true,
			EnableWebClient: true,
			EnableRESTAPI:   true,
		},
		enableWebAdmin:  true,
		enableWebClient: true,
		enableRESTAPI:   true,
	}
	server.initializeRouter()
	testServer := httptest.NewServer(server.router)
	defer testServer.Close()

	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, tokenPath, nil)
	require.NoError(t, err)
	req.SetBasicAuth(defaultAdminUsername, defaultAdminPass)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]any
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.NoError(t, err)
	accessToken := resp["access_token"]
	require.NotEmpty(t, accessToken)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	// change the token validation mode
	tokenValidationMode = 2
	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	// Now update the admin
	admin, err := dataprovider.AdminExists(defaultAdminUsername)
	assert.NoError(t, err)
	err = dataprovider.UpdateAdmin(&admin, "", "", "")
	assert.NoError(t, err)
	// token validation mode is 0, the old token is still valid
	tokenValidationMode = 0
	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	// change the token validation mode
	tokenValidationMode = 2
	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	// the token is invalidated, changing the validation mode has no effect
	tokenValidationMode = 0
	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, versionPath, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	userPwd := "pwd"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: defeaultUsername,
			Password: userPwd,
			HomeDir:  filepath.Join(os.TempDir(), defeaultUsername),
			Status:   1,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	err = dataprovider.AddUser(&user, "", "", "")
	assert.NoError(t, err)

	defer func() {
		dataprovider.DeleteUser(defeaultUsername, "", "", "") //nolint:errcheck
	}()

	tokenValidationMode = 2
	req, err = http.NewRequest(http.MethodGet, webClientLoginPath, nil)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	loginCookie := strings.Split(rr.Header().Get("Set-Cookie"), ";")[0]
	assert.NotEmpty(t, loginCookie)
	csrfToken, err := getCSRFTokenFromBody(rr.Body)
	assert.NoError(t, err)
	assert.NotEmpty(t, csrfToken)
	// Now login
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	form.Set("username", defeaultUsername)
	form.Set("password", userPwd)
	req, err = http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.Header.Set("Cookie", loginCookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code)
	userCookie := strings.Split(rr.Header().Get("Set-Cookie"), ";")[0]
	assert.NotEmpty(t, userCookie)
	// Test a WebClient page and a JSON API
	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", userCookie)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, webClientProfilePath, nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", userCookie)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	csrfToken, err = getCSRFTokenFromBody(rr.Body)
	assert.NoError(t, err)
	assert.NotEmpty(t, csrfToken)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, webClientFilePath+"?path=missing.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", userCookie)
	req.Header.Set(csrfHeaderToken, csrfToken)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	tokenValidationMode = 0
	err = dataprovider.DeleteUser(defeaultUsername, "", "", "")
	assert.NoError(t, err)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, webClientFilePath+"?path=missing.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", userCookie)
	req.Header.Set(csrfHeaderToken, csrfToken)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	tokenValidationMode = 2
	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, webClientFilePath+"?path=missing.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", userCookie)
	req.Header.Set(csrfHeaderToken, csrfToken)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code)

	tokenValidationMode = 0
}

func TestUpdateWebAdminInvalidClaims(t *testing.T) {
	server := httpdServer{}
	server.initializeRouter()

	rr := httptest.NewRecorder()
	admin := dataprovider.Admin{
		Username: "",
		Password: "password",
	}
	c := jwtTokenClaims{
		Username:    admin.Username,
		Permissions: admin.Permissions,
		Signature:   admin.GetSignature(),
	}
	token, err := c.createTokenResponse(server.tokenAuth, tokenAudienceWebAdmin, "")
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, webAdminPath, nil)
	assert.NoError(t, err)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	parsedToken, err := jwtauth.VerifyRequest(server.tokenAuth, req, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx := req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)

	form := make(url.Values)
	form.Set(csrfFormToken, createCSRFToken(rr, req, server.csrfTokenAuth, "", webBaseAdminPath))
	form.Set("status", "1")
	form.Set("default_users_expiration", "30")
	req, err = http.NewRequest(http.MethodPost, path.Join(webAdminPath, "admin"), bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("username", "admin")
	req = req.WithContext(ctx)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleWebUpdateAdminPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)
}

func TestRetentionInvalidTokenClaims(t *testing.T) {
	username := "retentionuser"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Password: "pwd",
			HomeDir:  filepath.Join(os.TempDir(), username),
			Status:   1,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.Filters.AllowAPIKeyAuth = true
	err := dataprovider.AddUser(&user, "", "", "")
	assert.NoError(t, err)
	folderRetention := []dataprovider.FolderRetention{
		{
			Path:            "/",
			Retention:       0,
			DeleteEmptyDirs: true,
		},
	}
	asJSON, err := json.Marshal(folderRetention)
	assert.NoError(t, err)
	req, _ := http.NewRequest(http.MethodPost, retentionBasePath+"/"+username+"/check?notifications=Email", bytes.NewBuffer(asJSON))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("username", username)

	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), jwtauth.ErrorCtxKey, errors.New("error")))
	rr := httptest.NewRecorder()
	startRetentionCheck(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)
}

func TestUpdateSMTPSecrets(t *testing.T) {
	currentConfigs := &dataprovider.SMTPConfigs{
		OAuth2: dataprovider.SMTPOAuth2{
			ClientSecret: kms.NewPlainSecret("client secret"),
			RefreshToken: kms.NewPlainSecret("refresh token"),
		},
	}
	redactedClientSecret := kms.NewPlainSecret("secret")
	redactedRefreshToken := kms.NewPlainSecret("token")
	redactedClientSecret.SetStatus(sdkkms.SecretStatusRedacted)
	redactedRefreshToken.SetStatus(sdkkms.SecretStatusRedacted)
	newConfigs := &dataprovider.SMTPConfigs{
		Password: kms.NewPlainSecret("pwd"),
		OAuth2: dataprovider.SMTPOAuth2{
			ClientSecret: redactedClientSecret,
			RefreshToken: redactedRefreshToken,
		},
	}
	updateSMTPSecrets(newConfigs, currentConfigs)
	assert.Nil(t, currentConfigs.Password)
	assert.NotNil(t, newConfigs.Password)
	assert.Equal(t, currentConfigs.OAuth2.ClientSecret, newConfigs.OAuth2.ClientSecret)
	assert.Equal(t, currentConfigs.OAuth2.RefreshToken, newConfigs.OAuth2.RefreshToken)

	clientSecret := kms.NewPlainSecret("plain secret")
	refreshToken := kms.NewPlainSecret("plain token")
	newConfigs = &dataprovider.SMTPConfigs{
		Password: kms.NewPlainSecret("pwd"),
		OAuth2: dataprovider.SMTPOAuth2{
			ClientSecret: clientSecret,
			RefreshToken: refreshToken,
		},
	}
	updateSMTPSecrets(newConfigs, currentConfigs)
	assert.Equal(t, clientSecret, newConfigs.OAuth2.ClientSecret)
	assert.Equal(t, refreshToken, newConfigs.OAuth2.RefreshToken)
}

func TestOAuth2Redirect(t *testing.T) {
	server := httpdServer{}
	server.initializeRouter()

	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, webOAuth2RedirectPath+"?state=invalid", nil)
	assert.NoError(t, err)
	server.handleOAuth2TokenRedirect(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nOAuth2ErrorTitle)

	ip := "127.1.1.4"
	tokenString := createOAuth2Token(server.csrfTokenAuth, xid.New().String(), ip)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, webOAuth2RedirectPath+"?state="+tokenString, nil) //nolint:goconst
	assert.NoError(t, err)
	req.RemoteAddr = ip
	server.handleOAuth2TokenRedirect(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nOAuth2ErrorValidateState)
}

func TestOAuth2Token(t *testing.T) {
	server := httpdServer{}
	server.initializeRouter()
	// invalid token
	_, err := verifyOAuth2Token(server.csrfTokenAuth, "token", "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to verify OAuth2 state")
	}
	// bad audience
	claims := make(map[string]any)
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(getTokenDuration(tokenAudienceAPI))
	claims[jwt.AudienceKey] = []string{tokenAudienceAPI}

	_, tokenString, err := server.csrfTokenAuth.Encode(claims)
	assert.NoError(t, err)
	_, err = verifyOAuth2Token(server.csrfTokenAuth, tokenString, "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid OAuth2 state")
	}
	// bad IP
	tokenString = createOAuth2Token(server.csrfTokenAuth, "state", "127.1.1.1")
	_, err = verifyOAuth2Token(server.csrfTokenAuth, tokenString, "127.1.1.2")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid OAuth2 state")
	}
	// ok
	state := xid.New().String()
	tokenString = createOAuth2Token(server.csrfTokenAuth, state, "127.1.1.3")
	s, err := verifyOAuth2Token(server.csrfTokenAuth, tokenString, "127.1.1.3")
	assert.NoError(t, err)
	assert.Equal(t, state, s)
	// no jti
	claims = make(map[string]any)

	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(getTokenDuration(tokenAudienceOAuth2))
	claims[jwt.AudienceKey] = []string{tokenAudienceOAuth2, "127.1.1.4"}
	_, tokenString, err = server.csrfTokenAuth.Encode(claims)
	assert.NoError(t, err)
	_, err = verifyOAuth2Token(server.csrfTokenAuth, tokenString, "127.1.1.4")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid OAuth2 state")
	}
	// encode error
	server.csrfTokenAuth = jwtauth.New("HT256", util.GenerateRandomBytes(32), nil)
	tokenString = createOAuth2Token(server.csrfTokenAuth, xid.New().String(), "")
	assert.Empty(t, tokenString)

	rr := httptest.NewRecorder()
	testReq := make(map[string]any)
	testReq["base_redirect_url"] = "http://localhost:8082"
	asJSON, err := json.Marshal(testReq)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, webOAuth2TokenPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	server.handleSMTPOAuth2TokenRequestPost(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "unable to create state token")
}

func TestCSRFToken(t *testing.T) {
	server := httpdServer{}
	server.initializeRouter()
	// invalid token
	req := &http.Request{}
	err := verifyCSRFToken(req, server.csrfTokenAuth)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to verify form token")
	}
	// bad audience
	claims := make(map[string]any)
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(getTokenDuration(tokenAudienceAPI))
	claims[jwt.AudienceKey] = []string{tokenAudienceAPI}

	_, tokenString, err := server.csrfTokenAuth.Encode(claims)
	assert.NoError(t, err)
	values := url.Values{}
	values.Set(csrfFormToken, tokenString)
	req.Form = values
	err = verifyCSRFToken(req, server.csrfTokenAuth)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "form token is not valid")
	}

	// bad IP
	req.RemoteAddr = "127.1.1.1"
	tokenString = createCSRFToken(httptest.NewRecorder(), req, server.csrfTokenAuth, "", webBaseAdminPath)
	values.Set(csrfFormToken, tokenString)
	req.Form = values
	req.RemoteAddr = "127.1.1.2"
	err = verifyCSRFToken(req, server.csrfTokenAuth)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "form token is not valid")
	}

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(getTokenDuration(tokenAudienceAPI))
	claims[jwt.AudienceKey] = []string{tokenAudienceAPI}
	_, tokenString, err = server.csrfTokenAuth.Encode(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	r := GetHTTPRouter(Binding{
		Address:         "",
		Port:            8080,
		EnableWebAdmin:  true,
		EnableWebClient: true,
		EnableRESTAPI:   true,
		RenderOpenAPI:   true,
	})
	fn := server.verifyCSRFHeader(r)
	rr := httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodDelete, path.Join(userPath, "username"), nil)
	fn.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token")

	// invalid audience
	req.Header.Set(csrfHeaderToken, tokenString)
	rr = httptest.NewRecorder()
	fn.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "the token is not valid")

	// invalid IP
	tokenString = createCSRFToken(httptest.NewRecorder(), req, server.csrfTokenAuth, "", webBaseAdminPath)
	req.Header.Set(csrfHeaderToken, tokenString)
	req.RemoteAddr = "172.16.1.2"
	rr = httptest.NewRecorder()
	fn.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "the token is not valid")

	csrfTokenAuth := jwtauth.New("PS256", util.GenerateRandomBytes(32), nil)
	tokenString = createCSRFToken(httptest.NewRecorder(), req, csrfTokenAuth, "", webBaseAdminPath)
	assert.Empty(t, tokenString)
	rr = httptest.NewRecorder()
	createLoginCookie(rr, req, csrfTokenAuth, "", webBaseAdminPath, req.RemoteAddr)
	assert.Empty(t, rr.Header().Get("Set-Cookie"))
}

func TestCreateShareCookieError(t *testing.T) {
	username := "share_user"
	pwd := util.GenerateUniqueID()
	user := &dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Password: pwd,
			HomeDir:  filepath.Join(os.TempDir(), username),
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
	}
	err := dataprovider.AddUser(user, "", "", "")
	assert.NoError(t, err)
	share := &dataprovider.Share{
		Name:     "test share cookie error",
		ShareID:  util.GenerateUniqueID(),
		Scope:    dataprovider.ShareScopeRead,
		Password: pwd,
		Paths:    []string{"/"},
		Username: username,
	}
	err = dataprovider.AddShare(share, "", "", "")
	assert.NoError(t, err)

	server := httpdServer{
		tokenAuth:     jwtauth.New("TS256", util.GenerateRandomBytes(32), nil),
		csrfTokenAuth: jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil),
	}

	c := jwtTokenClaims{
		JwtID: xid.New().String(),
	}
	resp, err := c.createTokenResponse(server.csrfTokenAuth, tokenAudienceWebLogin, "127.0.0.1")
	assert.NoError(t, err)
	parsedToken, err := jwtauth.VerifyToken(server.csrfTokenAuth, resp["access_token"].(string))
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, path.Join(webClientPubSharesPath, share.ShareID, "login"), nil)
	assert.NoError(t, err)
	req.RemoteAddr = "127.0.0.1:4567"
	ctx := req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)

	form := make(url.Values)
	form.Set("share_password", pwd)
	form.Set(csrfFormToken, createCSRFToken(httptest.NewRecorder(), req, server.csrfTokenAuth, "", webBaseClientPath))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", share.ShareID)
	rr := httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, path.Join(webClientPubSharesPath, share.ShareID, "login"),
		bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = "127.0.0.1:2345"
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", resp["access_token"]))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	server.handleClientShareLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nError500Message)

	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)
}

func TestCreateTokenError(t *testing.T) {
	server := httpdServer{
		tokenAuth:     jwtauth.New("PS256", util.GenerateRandomBytes(32), nil),
		csrfTokenAuth: jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil),
	}
	rr := httptest.NewRecorder()
	admin := dataprovider.Admin{
		Username: defaultAdminUsername,
		Password: "password",
	}
	req, _ := http.NewRequest(http.MethodGet, tokenPath, nil)

	server.generateAndSendToken(rr, req, admin, "")
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	rr = httptest.NewRecorder()
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "u",
			Password: util.GenerateUniqueID(),
		},
	}
	req, _ = http.NewRequest(http.MethodGet, userTokenPath, nil)

	server.generateAndSendUserToken(rr, req, "", user)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	c := jwtTokenClaims{
		JwtID: xid.New().String(),
	}
	token, err := c.createTokenResponse(server.csrfTokenAuth, tokenAudienceWebLogin, "")
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webAdminLoginPath, nil)
	assert.NoError(t, err)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	parsedToken, err := jwtauth.VerifyRequest(server.csrfTokenAuth, req, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx := req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)

	rr = httptest.NewRecorder()
	form := make(url.Values)
	form.Set("username", admin.Username)
	form.Set("password", admin.Password)
	form.Set(csrfFormToken, createCSRFToken(rr, req, server.csrfTokenAuth, xid.New().String(), webBaseAdminPath))
	cookie := rr.Header().Get("Set-Cookie")
	assert.NotEmpty(t, cookie)
	req, _ = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parsedToken, err = jwtauth.VerifyRequest(server.csrfTokenAuth, req, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx = req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)
	server.handleWebAdminLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	// req with no content type
	req, _ = http.NewRequest(http.MethodPost, webAdminLoginPath, nil)
	rr = httptest.NewRecorder()
	server.handleWebAdminLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	req, _ = http.NewRequest(http.MethodPost, webAdminSetupPath, nil)
	rr = httptest.NewRecorder()
	server.loginAdmin(rr, req, &admin, false, nil, "")
	// req with no POST body
	req, _ = http.NewRequest(http.MethodGet, webAdminLoginPath+"?a=a%C3%AO%GG", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAdminLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	req, _ = http.NewRequest(http.MethodGet, webAdminLoginPath+"?a=a%C3%A1%G2", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAdminChangePwdPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodGet, webAdminLoginPath+"?a=a%C3%A2%G3", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = getAdminFromPostFields(req)
	assert.Error(t, err)

	req, _ = http.NewRequest(http.MethodPost, webAdminEventActionPath+"?a=a%C3%A2%GG", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = getEventActionFromPostFields(req)
	assert.Error(t, err)

	req, _ = http.NewRequest(http.MethodPost, webAdminEventRulePath+"?a=a%C3%A3%GG", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = getEventRuleFromPostFields(req)
	assert.Error(t, err)

	req, _ = http.NewRequest(http.MethodPost, webIPListPath+"/1?a=a%C3%AO%GG", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = getIPListEntryFromPostFields(req, dataprovider.IPListTypeAllowList)
	assert.Error(t, err)

	req, _ = http.NewRequest(http.MethodPost, path.Join(webClientSharePath, "shareID", "login?a=a%C3%AO%GG"), bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleClientShareLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	req, _ = http.NewRequest(http.MethodPost, webClientLoginPath+"?a=a%C3%AO%GG", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	req, _ = http.NewRequest(http.MethodPost, webChangeClientPwdPath+"?a=a%C3%AO%GA", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientChangePwdPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath+"?a=a%C3%AO%GB", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientProfilePost(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())

	req, _ = http.NewRequest(http.MethodPost, webAdminProfilePath+"?a=a%C3%AO%GB", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAdminProfilePost(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())

	req, _ = http.NewRequest(http.MethodPost, webAdminTwoFactorPath+"?a=a%C3%AO%GC", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAdminTwoFactorPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath+"?a=a%C3%AO%GD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAdminTwoFactorRecoveryPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodPost, webClientTwoFactorPath+"?a=a%C3%AO%GC", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientTwoFactorPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath+"?a=a%C3%AO%GD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientTwoFactorRecoveryPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodPost, webAdminForgotPwdPath+"?a=a%C3%A1%GD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAdminForgotPwdPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodPost, webClientForgotPwdPath+"?a=a%C2%A1%GD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientForgotPwdPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodPost, webAdminResetPwdPath+"?a=a%C3%AO%JD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAdminPasswordResetPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodPost, webAdminRolePath+"?a=a%C3%AO%JE", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAddRolePost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodPost, webClientResetPwdPath+"?a=a%C3%AO%JD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientPasswordResetPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidForm)

	req, _ = http.NewRequest(http.MethodPost, webChangeClientPwdPath+"?a=a%K3%AO%GA", bytes.NewBuffer([]byte(form.Encode())))
	_, err = getShareFromPostFields(req)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid URL escape")
	}

	username := "webclientuser"
	user = dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:    username,
			Password:    "clientpwd",
			HomeDir:     filepath.Join(os.TempDir(), username),
			Status:      1,
			Description: "test user",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	user.Filters.AllowAPIKeyAuth = true
	err = dataprovider.AddUser(&user, "", "", "")
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webClientLoginPath, nil)
	assert.NoError(t, err)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	parsedToken, err = jwtauth.VerifyRequest(server.csrfTokenAuth, req, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx = req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)

	rr = httptest.NewRecorder()
	form = make(url.Values)
	form.Set("username", user.Username)
	form.Set("password", "clientpwd")
	form.Set(csrfFormToken, createCSRFToken(rr, req, server.csrfTokenAuth, "", webBaseClientPath))
	req, _ = http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.handleWebClientLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	err = authenticateUserWithAPIKey(username, "", server.tokenAuth, req)
	assert.Error(t, err)

	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.HomeDir)
	assert.NoError(t, err)

	admin.Username += "1"
	admin.Status = 1
	admin.Filters.AllowAPIKeyAuth = true
	admin.Permissions = []string{dataprovider.PermAdminAny}
	err = dataprovider.AddAdmin(&admin, "", "", "")
	assert.NoError(t, err)

	err = authenticateAdminWithAPIKey(admin.Username, "", server.tokenAuth, req)
	assert.Error(t, err)

	err = dataprovider.DeleteAdmin(admin.Username, "", "", "")
	assert.NoError(t, err)
}

func TestAPIKeyAuthForbidden(t *testing.T) {
	r := GetHTTPRouter(Binding{
		Address:         "",
		Port:            8080,
		EnableWebAdmin:  true,
		EnableWebClient: true,
		EnableRESTAPI:   true,
		RenderOpenAPI:   true,
	})
	fn := forbidAPIKeyAuthentication(r)
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, versionPath, nil)
	fn.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")
}

func TestJWTTokenValidation(t *testing.T) {
	tokenAuth := jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil)
	claims := make(map[string]any)
	claims["username"] = defaultAdminUsername
	claims[jwt.ExpirationKey] = time.Now().UTC().Add(-1 * time.Hour)
	token, _, err := tokenAuth.Encode(claims)
	assert.NoError(t, err)

	server := httpdServer{
		binding: Binding{
			Address:         "",
			Port:            8080,
			EnableWebAdmin:  true,
			EnableWebClient: true,
			EnableRESTAPI:   true,
			RenderOpenAPI:   true,
		},
	}
	server.initializeRouter()
	r := server.router
	fn := jwtAuthenticatorAPI(r)
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, userPath, nil)
	ctx := jwtauth.NewContext(req.Context(), token, nil)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	fn = jwtAuthenticatorWebAdmin(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webUserPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))

	fn = jwtAuthenticatorWebClient(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))

	errTest := errors.New("test error")
	permFn := server.checkPerms(dataprovider.PermAdminAny)
	fn = permFn(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, userPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, errTest)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	permFn = server.checkPerms(dataprovider.PermAdminAny)
	fn = permFn(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webUserPath, nil)
	req.RequestURI = webUserPath
	ctx = jwtauth.NewContext(req.Context(), token, errTest)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	permClientFn := server.checkHTTPUserPerm(sdk.WebClientPubKeyChangeDisabled)
	fn = permClientFn(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, nil)
	req.RequestURI = webClientProfilePath
	ctx = jwtauth.NewContext(req.Context(), token, errTest)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, userProfilePath, nil)
	req.RequestURI = userProfilePath
	ctx = jwtauth.NewContext(req.Context(), token, errTest)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	fn = server.checkAuthRequirements(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, webClientProfilePath, nil)
	req.RequestURI = webClientProfilePath
	ctx = jwtauth.NewContext(req.Context(), token, errTest)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	fn = server.checkAuthRequirements(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, webGroupsPath, nil)
	req.RequestURI = webGroupsPath
	ctx = jwtauth.NewContext(req.Context(), token, errTest)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, userSharesPath, nil)
	req.RequestURI = userSharesPath
	ctx = jwtauth.NewContext(req.Context(), token, errTest)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestUpdateContextFromCookie(t *testing.T) {
	server := httpdServer{
		tokenAuth: jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil),
	}
	req, _ := http.NewRequest(http.MethodGet, tokenPath, nil)
	claims := make(map[string]any)
	claims["a"] = "b"
	token, _, err := server.tokenAuth.Encode(claims)
	assert.NoError(t, err)

	ctx := jwtauth.NewContext(req.Context(), token, nil)
	server.updateContextFromCookie(req.WithContext(ctx))
}

func TestCookieExpiration(t *testing.T) {
	server := httpdServer{
		tokenAuth: jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil),
	}
	err := errors.New("test error")
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, tokenPath, nil)
	ctx := jwtauth.NewContext(req.Context(), nil, err)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie := rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	claims := make(map[string]any)
	claims["a"] = "b"
	token, _, err := server.tokenAuth.Encode(claims)
	assert.NoError(t, err)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	admin := dataprovider.Admin{
		Username:    "newtestadmin",
		Password:    "password",
		Permissions: []string{dataprovider.PermAdminAny},
	}
	claims = make(map[string]any)
	claims[claimUsernameKey] = admin.Username
	claims[claimPermissionsKey] = admin.Permissions
	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.SubjectKey] = admin.GetSignature()
	claims[jwt.ExpirationKey] = time.Now().Add(1 * time.Minute)
	claims[jwt.AudienceKey] = []string{tokenAudienceAPI}
	token, _, err = server.tokenAuth.Encode(claims)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	admin.Status = 0
	err = dataprovider.AddAdmin(&admin, "", "", "")
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	admin.Status = 1
	admin.Filters.AllowList = []string{"172.16.1.0/24"}
	err = dataprovider.UpdateAdmin(&admin, "", "", "")
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	admin, err = dataprovider.AdminExists(admin.Username)
	assert.NoError(t, err)
	tokenID := xid.New().String()
	claims = make(map[string]any)
	claims[claimUsernameKey] = admin.Username
	claims[claimPermissionsKey] = admin.Permissions
	claims[jwt.JwtIDKey] = tokenID
	claims[jwt.IssuedAtKey] = time.Now()
	claims[jwt.SubjectKey] = admin.GetSignature()
	claims[jwt.ExpirationKey] = time.Now().Add(1 * time.Minute)
	claims[jwt.AudienceKey] = []string{tokenAudienceAPI}
	token, _, err = server.tokenAuth.Encode(claims)
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	req.RemoteAddr = "192.168.8.1:1234"
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	req, _ = http.NewRequest(http.MethodGet, tokenPath, nil)
	req.RemoteAddr = "172.16.1.12:4567"
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.True(t, strings.HasPrefix(cookie, "jwt="))
	req.Header.Set("Cookie", cookie)
	token, err = jwtauth.VerifyRequest(server.tokenAuth, req, jwtauth.TokenFromCookie)
	if assert.NoError(t, err) {
		assert.Equal(t, tokenID, token.JwtID())
	}

	err = dataprovider.DeleteAdmin(admin.Username, "", "", "")
	assert.NoError(t, err)
	// now check client cookie expiration
	username := "client"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username:    username,
			Password:    "clientpwd",
			HomeDir:     filepath.Join(os.TempDir(), username),
			Status:      1,
			Description: "test user",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{"*"}

	claims = make(map[string]any)
	claims[claimUsernameKey] = user.Username
	claims[claimPermissionsKey] = user.Filters.WebClient
	claims[jwt.JwtIDKey] = tokenID
	claims[jwt.IssuedAtKey] = time.Now()
	claims[jwt.SubjectKey] = user.GetSignature()
	claims[jwt.ExpirationKey] = time.Now().Add(1 * time.Minute)
	claims[jwt.AudienceKey] = []string{tokenAudienceWebClient}
	token, _, err = server.tokenAuth.Encode(claims)
	assert.NoError(t, err)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)
	// the password will be hashed and so the signature will change
	err = dataprovider.AddUser(&user, "", "", "")
	assert.NoError(t, err)
	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	user, err = dataprovider.UserExists(user.Username, "")
	assert.NoError(t, err)
	user.Filters.AllowedIP = []string{"172.16.4.0/24"}
	err = dataprovider.UpdateUser(&user, "", "", "")
	assert.NoError(t, err)

	user, err = dataprovider.UserExists(user.Username, "")
	assert.NoError(t, err)
	issuedAt := time.Now().Add(-1 * time.Minute)
	expiresAt := time.Now().Add(1 * time.Minute)
	claims = make(map[string]any)
	claims[claimUsernameKey] = user.Username
	claims[claimPermissionsKey] = user.Filters.WebClient
	claims[jwt.JwtIDKey] = tokenID
	claims[jwt.IssuedAtKey] = issuedAt
	claims[jwt.SubjectKey] = user.GetSignature()
	claims[jwt.ExpirationKey] = expiresAt
	claims[jwt.AudienceKey] = []string{tokenAudienceWebClient}
	token, _, err = server.tokenAuth.Encode(claims)
	assert.NoError(t, err)

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.RemoteAddr = "172.16.3.12:4567"
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.RemoteAddr = "172.16.4.16:4567"
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.NotEmpty(t, cookie)
	req.Header.Set("Cookie", cookie)
	token, err = jwtauth.VerifyRequest(server.tokenAuth, req, jwtauth.TokenFromCookie)
	if assert.NoError(t, err) {
		assert.Equal(t, tokenID, token.JwtID())
		assert.Equal(t, issuedAt.Unix(), token.IssuedAt().Unix())
		assert.NotEqual(t, expiresAt.Unix(), token.Expiration().Unix())
	}
	// test a cookie issued more that 12 hours ago
	claims[jwt.IssuedAtKey] = time.Now().Add(-24 * time.Hour)
	token, _, err = server.tokenAuth.Encode(claims)
	assert.NoError(t, err)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.RemoteAddr = "172.16.4.16:6789"
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	// test a disabled user
	user.Status = 0
	err = dataprovider.UpdateUser(&user, "", "", "")
	assert.NoError(t, err)
	user, err = dataprovider.UserExists(user.Username, "")
	assert.NoError(t, err)

	claims = make(map[string]any)
	claims[claimUsernameKey] = user.Username
	claims[claimPermissionsKey] = user.Filters.WebClient
	claims[jwt.JwtIDKey] = tokenID
	claims[jwt.IssuedAtKey] = issuedAt
	claims[jwt.SubjectKey] = user.GetSignature()
	claims[jwt.ExpirationKey] = time.Now().Add(1 * time.Minute)
	claims[jwt.AudienceKey] = []string{tokenAudienceWebClient}
	token, _, err = server.tokenAuth.Encode(claims)
	assert.NoError(t, err)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, nil)
	server.checkCookieExpiration(rr, req.WithContext(ctx))
	cookie = rr.Header().Get("Set-Cookie")
	assert.Empty(t, cookie)

	err = dataprovider.DeleteUser(user.Username, "", "", "")
	assert.NoError(t, err)
}

func TestGetURLParam(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, adminPwdPath, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("val", "testuser%C3%A0")
	rctx.URLParams.Add("inval", "testuser%C3%AO%GG")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	escaped := getURLParam(req, "val")
	assert.Equal(t, "testuserà", escaped)
	escaped = getURLParam(req, "inval")
	assert.Equal(t, "testuser%C3%AO%GG", escaped)
}

func TestChangePwdValidationErrors(t *testing.T) {
	err := doChangeAdminPassword(nil, "", "", "")
	require.Error(t, err)
	err = doChangeAdminPassword(nil, "a", "b", "c")
	require.Error(t, err)
	err = doChangeAdminPassword(nil, "a", "a", "a")
	require.Error(t, err)

	req, _ := http.NewRequest(http.MethodPut, adminPwdPath, nil)
	err = doChangeAdminPassword(req, "currentpwd", "newpwd", "newpwd")
	assert.Error(t, err)
}

func TestRenderUnexistingFolder(t *testing.T) {
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, folderPath, nil)
	renderFolder(rr, req, "path not mapped", &jwtTokenClaims{}, http.StatusOK)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestCloseConnectionHandler(t *testing.T) {
	tokenAuth := jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil)
	claims := make(map[string]any)
	claims["username"] = defaultAdminUsername
	claims[jwt.ExpirationKey] = time.Now().UTC().Add(1 * time.Hour)
	token, _, err := tokenAuth.Encode(claims)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodDelete, activeConnectionsPath+"/connectionID", nil)
	assert.NoError(t, err)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("connectionID", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), jwtauth.TokenCtxKey, token))
	rr := httptest.NewRecorder()
	handleCloseConnection(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "connectionID is mandatory")
}

func TestRenderInvalidTemplate(t *testing.T) {
	tmpl, err := template.New("test").Parse("{{.Count}}")
	if assert.NoError(t, err) {
		noMatchTmpl := "no_match"
		adminTemplates[noMatchTmpl] = tmpl
		rw := httptest.NewRecorder()
		renderAdminTemplate(rw, noMatchTmpl, map[string]string{})
		assert.Equal(t, http.StatusInternalServerError, rw.Code)
		clientTemplates[noMatchTmpl] = tmpl
		renderClientTemplate(rw, noMatchTmpl, map[string]string{})
		assert.Equal(t, http.StatusInternalServerError, rw.Code)
	}
}

func TestQuotaScanInvalidFs(t *testing.T) {
	user := &dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "test",
			HomeDir:  os.TempDir(),
		},
		FsConfig: vfs.Filesystem{
			Provider: sdk.S3FilesystemProvider,
		},
	}
	common.QuotaScans.AddUserQuotaScan(user.Username, "")
	err := doUserQuotaScan(user)
	assert.Error(t, err)
}

func TestVerifyTLSConnection(t *testing.T) {
	oldCertMgr := certMgr

	caCrlPath := filepath.Join(os.TempDir(), "testcrl.crt")
	certPath := filepath.Join(os.TempDir(), "testh.crt")
	keyPath := filepath.Join(os.TempDir(), "testh.key")
	err := os.WriteFile(caCrlPath, []byte(caCRL), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(certPath, []byte(httpdCert), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(httpdKey), os.ModePerm)
	assert.NoError(t, err)

	keyPairs := []common.TLSKeyPair{
		{
			Cert: certPath,
			Key:  keyPath,
			ID:   common.DefaultTLSKeyPaidID,
		},
	}
	certMgr, err = common.NewCertManager(keyPairs, "", "httpd_test")
	assert.NoError(t, err)

	certMgr.SetCARevocationLists([]string{caCrlPath})
	err = certMgr.LoadCRLs()
	assert.NoError(t, err)

	crt, err := tls.X509KeyPair([]byte(client1Crt), []byte(client1Key))
	assert.NoError(t, err)
	x509crt, err := x509.ParseCertificate(crt.Certificate[0])
	assert.NoError(t, err)

	server := httpdServer{}
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

func TestGetFolderFromTemplate(t *testing.T) {
	folder := vfs.BaseVirtualFolder{
		MappedPath:  "Folder%name%",
		Description: "Folder %name% desc",
	}
	folderName := "folderTemplate"
	folderTemplate := getFolderFromTemplate(folder, folderName)
	require.Equal(t, folderName, folderTemplate.Name)
	require.Equal(t, fmt.Sprintf("Folder%v", folderName), folderTemplate.MappedPath)
	require.Equal(t, fmt.Sprintf("Folder %v desc", folderName), folderTemplate.Description)

	folder.FsConfig.Provider = sdk.CryptedFilesystemProvider
	folder.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("%name%")
	folderTemplate = getFolderFromTemplate(folder, folderName)
	require.Equal(t, folderName, folderTemplate.FsConfig.CryptConfig.Passphrase.GetPayload())

	folder.FsConfig.Provider = sdk.GCSFilesystemProvider
	folder.FsConfig.GCSConfig.KeyPrefix = "prefix%name%/"
	folderTemplate = getFolderFromTemplate(folder, folderName)
	require.Equal(t, fmt.Sprintf("prefix%v/", folderName), folderTemplate.FsConfig.GCSConfig.KeyPrefix)

	folder.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	folder.FsConfig.AzBlobConfig.KeyPrefix = "a%name%"
	folder.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret("pwd%name%")
	folderTemplate = getFolderFromTemplate(folder, folderName)
	require.Equal(t, "a"+folderName, folderTemplate.FsConfig.AzBlobConfig.KeyPrefix)
	require.Equal(t, "pwd"+folderName, folderTemplate.FsConfig.AzBlobConfig.AccountKey.GetPayload())

	folder.FsConfig.Provider = sdk.SFTPFilesystemProvider
	folder.FsConfig.SFTPConfig.Prefix = "%name%"
	folder.FsConfig.SFTPConfig.Username = "sftp_%name%"
	folder.FsConfig.SFTPConfig.Password = kms.NewPlainSecret("sftp%name%")
	folderTemplate = getFolderFromTemplate(folder, folderName)
	require.Equal(t, folderName, folderTemplate.FsConfig.SFTPConfig.Prefix)
	require.Equal(t, "sftp_"+folderName, folderTemplate.FsConfig.SFTPConfig.Username)
	require.Equal(t, "sftp"+folderName, folderTemplate.FsConfig.SFTPConfig.Password.GetPayload())
}

func TestGetUserFromTemplate(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Status: 1,
		},
	}
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: "Folder%username%",
		},
	})

	username := "userTemplate"
	password := "pwdTemplate"
	templateFields := userTemplateFields{
		Username: username,
		Password: password,
	}

	userTemplate := getUserFromTemplate(user, templateFields)
	require.Len(t, userTemplate.VirtualFolders, 1)
	require.Equal(t, "Folder"+username, userTemplate.VirtualFolders[0].Name)

	user.FsConfig.Provider = sdk.CryptedFilesystemProvider
	user.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("%password%")
	userTemplate = getUserFromTemplate(user, templateFields)
	require.Equal(t, password, userTemplate.FsConfig.CryptConfig.Passphrase.GetPayload())

	user.FsConfig.Provider = sdk.GCSFilesystemProvider
	user.FsConfig.GCSConfig.KeyPrefix = "%username%%password%"
	userTemplate = getUserFromTemplate(user, templateFields)
	require.Equal(t, username+password, userTemplate.FsConfig.GCSConfig.KeyPrefix)

	user.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	user.FsConfig.AzBlobConfig.KeyPrefix = "a%username%"
	user.FsConfig.AzBlobConfig.AccountKey = kms.NewPlainSecret("pwd%password%%username%")
	userTemplate = getUserFromTemplate(user, templateFields)
	require.Equal(t, "a"+username, userTemplate.FsConfig.AzBlobConfig.KeyPrefix)
	require.Equal(t, "pwd"+password+username, userTemplate.FsConfig.AzBlobConfig.AccountKey.GetPayload())

	user.FsConfig.Provider = sdk.SFTPFilesystemProvider
	user.FsConfig.SFTPConfig.Prefix = "%username%"
	user.FsConfig.SFTPConfig.Username = "sftp_%username%"
	user.FsConfig.SFTPConfig.Password = kms.NewPlainSecret("sftp%password%")
	userTemplate = getUserFromTemplate(user, templateFields)
	require.Equal(t, username, userTemplate.FsConfig.SFTPConfig.Prefix)
	require.Equal(t, "sftp_"+username, userTemplate.FsConfig.SFTPConfig.Username)
	require.Equal(t, "sftp"+password, userTemplate.FsConfig.SFTPConfig.Password.GetPayload())
}

func TestJWTTokenCleanup(t *testing.T) {
	server := httpdServer{
		tokenAuth: jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil),
	}
	admin := dataprovider.Admin{
		Username:    "newtestadmin",
		Password:    "password",
		Permissions: []string{dataprovider.PermAdminAny},
	}
	claims := make(map[string]any)
	claims[claimUsernameKey] = admin.Username
	claims[claimPermissionsKey] = admin.Permissions
	claims[jwt.SubjectKey] = admin.GetSignature()
	claims[jwt.ExpirationKey] = time.Now().Add(1 * time.Minute)
	_, token, err := server.tokenAuth.Encode(claims)
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, versionPath, nil)
	assert.True(t, isTokenInvalidated(req))

	fakeToken := "abc"
	invalidateTokenString(req, fakeToken, -100*time.Millisecond)
	assert.True(t, invalidatedJWTTokens.Get(fakeToken))

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))

	invalidatedJWTTokens.Add(token, time.Now().Add(-getTokenDuration(tokenAudienceWebAdmin)).UTC())
	require.True(t, isTokenInvalidated(req))
	startCleanupTicker(100 * time.Millisecond)
	assert.Eventually(t, func() bool { return !isTokenInvalidated(req) }, 1*time.Second, 200*time.Millisecond)
	assert.False(t, invalidatedJWTTokens.Get(fakeToken))
	stopCleanupTicker()
}

func TestDbTokenManager(t *testing.T) {
	if !isSharedProviderSupported() {
		t.Skip("this test it is not available with this provider")
	}
	mgr := newTokenManager(1)
	dbTokenManager := mgr.(*dbTokenManager)
	testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiV2ViQWRtaW4iLCI6OjEiXSwiZXhwIjoxNjk4NjYwMDM4LCJqdGkiOiJja3ZuazVrYjF1aHUzZXRmZmhyZyIsIm5iZiI6MTY5ODY1ODgwOCwicGVybWlzc2lvbnMiOlsiKiJdLCJzdWIiOiIxNjk3ODIwNDM3NTMyIiwidXNlcm5hbWUiOiJhZG1pbiJ9.LXuFFksvnSuzHqHat6r70yR0jEulNRju7m7SaWrOfy8; csrftoken=mP0C7DqjwpAXsptO2gGCaYBkYw3oNMWB"
	key := dbTokenManager.getKey(testToken)
	require.Len(t, key, 64)
	dbTokenManager.Add(testToken, time.Now().Add(-getTokenDuration(tokenAudienceWebClient)).UTC())
	isInvalidated := dbTokenManager.Get(testToken)
	assert.True(t, isInvalidated)
	dbTokenManager.Cleanup()
	isInvalidated = dbTokenManager.Get(testToken)
	assert.False(t, isInvalidated)
	dbTokenManager.Add(testToken, time.Now().Add(getTokenDuration(tokenAudienceWebAdmin)).UTC())
	isInvalidated = dbTokenManager.Get(testToken)
	assert.True(t, isInvalidated)
	dbTokenManager.Cleanup()
	isInvalidated = dbTokenManager.Get(testToken)
	assert.True(t, isInvalidated)
	err := dataprovider.DeleteSharedSession(key, dataprovider.SessionTypeInvalidToken)
	assert.NoError(t, err)
}

func TestDatabaseSharedSessions(t *testing.T) {
	if !isSharedProviderSupported() {
		t.Skip("this test it is not available with this provider")
	}
	session1 := dataprovider.Session{
		Key:       "1",
		Data:      map[string]string{"a": "b"},
		Type:      dataprovider.SessionTypeOIDCAuth,
		Timestamp: 10,
	}
	err := dataprovider.AddSharedSession(session1)
	assert.NoError(t, err)
	// Adding another session with the same key but a different type should work
	session2 := session1
	session2.Type = dataprovider.SessionTypeOIDCToken
	err = dataprovider.AddSharedSession(session2)
	assert.NoError(t, err)
	err = dataprovider.DeleteSharedSession(session1.Key, dataprovider.SessionTypeInvalidToken)
	assert.ErrorIs(t, err, util.ErrNotFound)
	_, err = dataprovider.GetSharedSession(session1.Key, dataprovider.SessionTypeResetCode)
	assert.ErrorIs(t, err, util.ErrNotFound)
	session1Get, err := dataprovider.GetSharedSession(session1.Key, dataprovider.SessionTypeOIDCAuth)
	assert.NoError(t, err)
	assert.Equal(t, session1.Timestamp, session1Get.Timestamp)
	var stored map[string]string
	err = json.Unmarshal(session1Get.Data.([]byte), &stored)
	assert.NoError(t, err)
	assert.Equal(t, session1.Data, stored)
	session1.Timestamp = 20
	session1.Data = map[string]string{"c": "d"}
	err = dataprovider.AddSharedSession(session1)
	assert.NoError(t, err)
	session1Get, err = dataprovider.GetSharedSession(session1.Key, dataprovider.SessionTypeOIDCAuth)
	assert.NoError(t, err)
	assert.Equal(t, session1.Timestamp, session1Get.Timestamp)
	stored = make(map[string]string)
	err = json.Unmarshal(session1Get.Data.([]byte), &stored)
	assert.NoError(t, err)
	assert.Equal(t, session1.Data, stored)
	err = dataprovider.DeleteSharedSession(session1.Key, dataprovider.SessionTypeOIDCAuth)
	assert.NoError(t, err)
	err = dataprovider.DeleteSharedSession(session2.Key, dataprovider.SessionTypeOIDCToken)
	assert.NoError(t, err)
	_, err = dataprovider.GetSharedSession(session1.Key, dataprovider.SessionTypeOIDCAuth)
	assert.ErrorIs(t, err, util.ErrNotFound)
	_, err = dataprovider.GetSharedSession(session2.Key, dataprovider.SessionTypeOIDCToken)
	assert.ErrorIs(t, err, util.ErrNotFound)
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

func TestProxyListenerWrapper(t *testing.T) {
	b := Binding{
		ProxyMode: 0,
	}
	require.Nil(t, b.listenerWrapper())
	b.ProxyMode = 1
	require.NotNil(t, b.listenerWrapper())
}

func TestProxyHeaders(t *testing.T) {
	username := "adminTest"
	password := "testPwd"
	admin := dataprovider.Admin{
		Username:    username,
		Password:    password,
		Permissions: []string{dataprovider.PermAdminAny},
		Status:      1,
		Filters: dataprovider.AdminFilters{
			AllowList: []string{"172.19.2.0/24"},
		},
	}

	err := dataprovider.AddAdmin(&admin, "", "", "")
	assert.NoError(t, err)

	testIP := "10.29.1.9"
	validForwardedFor := "172.19.2.6"
	b := Binding{
		Address:             "",
		Port:                8080,
		EnableWebAdmin:      true,
		EnableWebClient:     false,
		EnableRESTAPI:       true,
		ProxyAllowed:        []string{testIP, "10.8.0.0/30"},
		ClientIPProxyHeader: "x-forwarded-for",
	}
	err = b.parseAllowedProxy()
	assert.NoError(t, err)
	server := newHttpdServer(b, "", "", CorsConfig{Enabled: true}, "")
	server.initializeRouter()
	testServer := httptest.NewServer(server.router)
	defer testServer.Close()

	req, err := http.NewRequest(http.MethodGet, tokenPath, nil)
	assert.NoError(t, err)
	req.Header.Set("X-Forwarded-For", validForwardedFor)
	req.Header.Set(xForwardedProto, "https")
	req.RemoteAddr = "127.0.0.1:123"
	req.SetBasicAuth(username, password)
	rr := httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.NotContains(t, rr.Body.String(), "login from IP 127.0.0.1 not allowed")

	req.RemoteAddr = testIP
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	req.RemoteAddr = "10.8.0.2"
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	req, err = http.NewRequest(http.MethodGet, webAdminLoginPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = testIP
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	cookie := rr.Header().Get("Set-Cookie")
	assert.NotEmpty(t, cookie)
	req.Header.Set("Cookie", cookie)
	parsedToken, err := jwtauth.VerifyRequest(server.csrfTokenAuth, req, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx := req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)

	form := make(url.Values)
	form.Set("username", username)
	form.Set("password", password)
	form.Set(csrfFormToken, createCSRFToken(httptest.NewRecorder(), req, server.csrfTokenAuth, "", webBaseAdminPath))
	req, err = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = testIP
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidCredentials)

	req, err = http.NewRequest(http.MethodGet, webAdminLoginPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = validForwardedFor
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	loginCookie := rr.Header().Get("Set-Cookie")
	assert.NotEmpty(t, loginCookie)
	req.Header.Set("Cookie", loginCookie)
	parsedToken, err = jwtauth.VerifyRequest(server.csrfTokenAuth, req, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx = req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)

	form.Set(csrfFormToken, createCSRFToken(httptest.NewRecorder(), req, server.csrfTokenAuth, "", webBaseAdminPath))
	req, err = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = testIP
	req.Header.Set("Cookie", loginCookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", validForwardedFor)
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	cookie = rr.Header().Get("Set-Cookie")
	assert.NotContains(t, cookie, "Secure")

	// The login cookie is invalidated after a successful login, the same request will fail
	req, err = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = testIP
	req.Header.Set("Cookie", loginCookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", validForwardedFor)
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidCSRF)

	req, err = http.NewRequest(http.MethodGet, webAdminLoginPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = validForwardedFor
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	loginCookie = rr.Header().Get("Set-Cookie")
	assert.NotEmpty(t, loginCookie)
	req.Header.Set("Cookie", loginCookie)
	parsedToken, err = jwtauth.VerifyRequest(server.csrfTokenAuth, req, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx = req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)

	form.Set(csrfFormToken, createCSRFToken(httptest.NewRecorder(), req, server.csrfTokenAuth, "", webBaseAdminPath))
	req, err = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = testIP
	req.Header.Set("Cookie", loginCookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", validForwardedFor)
	req.Header.Set(xForwardedProto, "https")
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	cookie = rr.Header().Get("Set-Cookie")
	assert.Contains(t, cookie, "Secure")

	req, err = http.NewRequest(http.MethodGet, webAdminLoginPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = validForwardedFor
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	loginCookie = rr.Header().Get("Set-Cookie")
	assert.NotEmpty(t, loginCookie)
	req.Header.Set("Cookie", loginCookie)
	parsedToken, err = jwtauth.VerifyRequest(server.csrfTokenAuth, req, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx = req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)

	form.Set(csrfFormToken, createCSRFToken(httptest.NewRecorder(), req, server.csrfTokenAuth, "", webBaseAdminPath))
	req, err = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = testIP
	req.Header.Set("Cookie", loginCookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", validForwardedFor)
	req.Header.Set(xForwardedProto, "http")
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	cookie = rr.Header().Get("Set-Cookie")
	assert.NotContains(t, cookie, "Secure")

	err = dataprovider.DeleteAdmin(username, "", "", "")
	assert.NoError(t, err)
}

func TestRecoverer(t *testing.T) {
	recoveryPath := "/recovery"
	b := Binding{
		Address:         "",
		Port:            8080,
		EnableWebAdmin:  true,
		EnableWebClient: false,
		EnableRESTAPI:   true,
	}
	server := newHttpdServer(b, "../static", "", CorsConfig{}, "../openapi")
	server.initializeRouter()
	server.router.Get(recoveryPath, func(_ http.ResponseWriter, _ *http.Request) {
		panic("panic")
	})
	testServer := httptest.NewServer(server.router)
	defer testServer.Close()

	req, err := http.NewRequest(http.MethodGet, recoveryPath, nil)
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())

	server.router = chi.NewRouter()
	server.router.Use(middleware.Recoverer)
	server.router.Get(recoveryPath, func(_ http.ResponseWriter, _ *http.Request) {
		panic("panic")
	})
	testServer = httptest.NewServer(server.router)
	defer testServer.Close()

	req, err = http.NewRequest(http.MethodGet, recoveryPath, nil)
	assert.NoError(t, err)
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
}

func TestStreamJSONArray(t *testing.T) {
	dataGetter := func(_, _ int) ([]byte, int, error) {
		return nil, 0, nil
	}
	rr := httptest.NewRecorder()
	streamJSONArray(rr, 10, dataGetter)
	assert.Equal(t, `[]`, rr.Body.String())

	data := []int{}
	for i := 0; i < 10; i++ {
		data = append(data, i)
	}

	dataGetter = func(_, offset int) ([]byte, int, error) {
		if offset >= len(data) {
			return nil, 0, nil
		}
		val := data[offset]
		data, err := json.Marshal([]int{val})
		return data, 1, err
	}

	rr = httptest.NewRecorder()
	streamJSONArray(rr, 1, dataGetter)
	assert.Equal(t, `[0,1,2,3,4,5,6,7,8,9]`, rr.Body.String())
}

func TestCompressorAbortHandler(t *testing.T) {
	defer func() {
		rcv := recover()
		assert.Equal(t, http.ErrAbortHandler, rcv)
	}()

	connection := &Connection{
		BaseConnection: common.NewBaseConnection(xid.New().String(), common.ProtocolHTTP, "", "", dataprovider.User{}),
		request:        nil,
	}
	share := &dataprovider.Share{}
	renderCompressedFiles(&failingWriter{}, connection, "", nil, share)
}

func TestStreamDataAbortHandler(t *testing.T) {
	defer func() {
		rcv := recover()
		assert.Equal(t, http.ErrAbortHandler, rcv)
	}()

	streamData(&failingWriter{}, []byte(`["a":"b"]`))
}

func TestZipErrors(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			HomeDir: filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(xid.New().String(), common.ProtocolHTTP, "", "", user),
		request:        nil,
	}

	testDir := filepath.Join(os.TempDir(), "testDir")
	err := os.MkdirAll(testDir, os.ModePerm)
	assert.NoError(t, err)

	wr := zip.NewWriter(&failingWriter{})
	err = wr.Close()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "write error")
	}

	err = addZipEntry(wr, connection, "/"+filepath.Base(testDir), "/", nil, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "write error")
	}
	err = addZipEntry(wr, connection, "/"+filepath.Base(testDir), "/", nil, 2000)
	assert.ErrorIs(t, err, util.ErrRecursionTooDeep)

	err = addZipEntry(wr, connection, "/"+filepath.Base(testDir), path.Join("/", filepath.Base(testDir), "dir"), nil, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is outside base dir")
	}

	testFilePath := filepath.Join(testDir, "ziptest.zip")
	err = os.WriteFile(testFilePath, util.GenerateRandomBytes(65535), os.ModePerm)
	assert.NoError(t, err)
	err = addZipEntry(wr, connection, path.Join("/", filepath.Base(testDir), filepath.Base(testFilePath)),
		"/"+filepath.Base(testDir), nil, 0)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "write error")
	}

	connection.User.Permissions["/"] = []string{dataprovider.PermListItems}
	err = addZipEntry(wr, connection, path.Join("/", filepath.Base(testDir), filepath.Base(testFilePath)),
		"/"+filepath.Base(testDir), nil, 0)
	assert.ErrorIs(t, err, os.ErrPermission)

	// creating a virtual folder to a missing path stat is ok but readdir fails
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: filepath.Join(os.TempDir(), "mapped"),
		},
		VirtualPath: "/vpath",
	})
	connection.User = user
	wr = zip.NewWriter(bytes.NewBuffer(make([]byte, 0)))
	err = addZipEntry(wr, connection, user.VirtualFolders[0].VirtualPath, "/", nil, 0)
	assert.Error(t, err)

	user.Filters.FilePatterns = append(user.Filters.FilePatterns, sdk.PatternsFilter{
		Path:           "/",
		DeniedPatterns: []string{"*.zip"},
	})
	err = addZipEntry(wr, connection, "/"+filepath.Base(testDir), "/", nil, 0)
	assert.ErrorIs(t, err, os.ErrPermission)

	err = os.RemoveAll(testDir)
	assert.NoError(t, err)
}

func TestWebAdminRedirect(t *testing.T) {
	b := Binding{
		Address:         "",
		Port:            8080,
		EnableWebAdmin:  true,
		EnableWebClient: false,
		EnableRESTAPI:   true,
	}
	server := newHttpdServer(b, "../static", "", CorsConfig{}, "../openapi")
	server.initializeRouter()
	testServer := httptest.NewServer(server.router)
	defer testServer.Close()

	req, err := http.NewRequest(http.MethodGet, webRootPath, nil)
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))

	req, err = http.NewRequest(http.MethodGet, webBasePath, nil)
	assert.NoError(t, err)
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))
}

func TestParseRangeRequests(t *testing.T) {
	// curl --verbose  "http://127.0.0.1:8080/static/css/sb-admin-2.min.css" -H "Range: bytes=24-24"
	fileSize := int64(169740)
	rangeHeader := "bytes=24-24"
	offset, size, err := parseRangeRequest(rangeHeader[6:], fileSize)
	require.NoError(t, err)
	resp := fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, fileSize)
	assert.Equal(t, "bytes 24-24/169740", resp)
	require.Equal(t, int64(1), size)
	// curl --verbose  "http://127.0.0.1:8080/static/css/sb-admin-2.min.css" -H "Range: bytes=24-"
	rangeHeader = "bytes=24-"
	offset, size, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.NoError(t, err)
	resp = fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, fileSize)
	assert.Equal(t, "bytes 24-169739/169740", resp)
	require.Equal(t, int64(169716), size)
	// curl --verbose  "http://127.0.0.1:8080/static/css/sb-admin-2.min.css" -H "Range: bytes=-1"
	rangeHeader = "bytes=-1"
	offset, size, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.NoError(t, err)
	resp = fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, fileSize)
	assert.Equal(t, "bytes 169739-169739/169740", resp)
	require.Equal(t, int64(1), size)
	// curl --verbose  "http://127.0.0.1:8080/static/css/sb-admin-2.min.css" -H "Range: bytes=-100"
	rangeHeader = "bytes=-100"
	offset, size, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.NoError(t, err)
	resp = fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, fileSize)
	assert.Equal(t, "bytes 169640-169739/169740", resp)
	require.Equal(t, int64(100), size)
	// curl --verbose  "http://127.0.0.1:8080/static/css/sb-admin-2.min.css" -H "Range: bytes=20-30"
	rangeHeader = "bytes=20-30"
	offset, size, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.NoError(t, err)
	resp = fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, fileSize)
	assert.Equal(t, "bytes 20-30/169740", resp)
	require.Equal(t, int64(11), size)
	// curl --verbose  "http://127.0.0.1:8080/static/css/sb-admin-2.min.css" -H "Range: bytes=20-169739"
	rangeHeader = "bytes=20-169739"
	offset, size, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.NoError(t, err)
	resp = fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, fileSize)
	assert.Equal(t, "bytes 20-169739/169740", resp)
	require.Equal(t, int64(169720), size)
	// curl --verbose  "http://127.0.0.1:8080/static/css/sb-admin-2.min.css" -H "Range: bytes=20-169740"
	rangeHeader = "bytes=20-169740"
	offset, size, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.NoError(t, err)
	resp = fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, fileSize)
	assert.Equal(t, "bytes 20-169739/169740", resp)
	require.Equal(t, int64(169720), size)
	// curl --verbose  "http://127.0.0.1:8080/static/css/sb-admin-2.min.css" -H "Range: bytes=20-169741"
	rangeHeader = "bytes=20-169741"
	offset, size, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.NoError(t, err)
	resp = fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, fileSize)
	assert.Equal(t, "bytes 20-169739/169740", resp)
	require.Equal(t, int64(169720), size)
	//curl --verbose  "http://127.0.0.1:8080/static/css/sb-admin-2.min.css" -H "Range: bytes=0-" > /dev/null
	rangeHeader = "bytes=0-"
	offset, size, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.NoError(t, err)
	resp = fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, fileSize)
	assert.Equal(t, "bytes 0-169739/169740", resp)
	require.Equal(t, int64(169740), size)
	// now test errors
	rangeHeader = "bytes=0-a"
	_, _, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.Error(t, err)
	rangeHeader = "bytes="
	_, _, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.Error(t, err)
	rangeHeader = "bytes=-"
	_, _, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.Error(t, err)
	rangeHeader = "bytes=500-300"
	_, _, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.Error(t, err)
	rangeHeader = "bytes=5000000"
	_, _, err = parseRangeRequest(rangeHeader[6:], fileSize)
	require.Error(t, err)
}

func TestRequestHeaderErrors(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.Header.Set("If-Unmodified-Since", "not a date")
	res := checkIfUnmodifiedSince(req, time.Now())
	assert.Equal(t, condNone, res)

	req, _ = http.NewRequest(http.MethodPost, webClientFilesPath, nil)
	res = checkIfModifiedSince(req, time.Now())
	assert.Equal(t, condNone, res)

	req, _ = http.NewRequest(http.MethodPost, webClientFilesPath, nil)
	res = checkIfRange(req, time.Now())
	assert.Equal(t, condNone, res)

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.Header.Set("If-Modified-Since", "not a date")
	res = checkIfModifiedSince(req, time.Now())
	assert.Equal(t, condNone, res)

	req, _ = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.Header.Set("If-Range", time.Now().Format(http.TimeFormat))
	res = checkIfRange(req, time.Time{})
	assert.Equal(t, condFalse, res)

	req.Header.Set("If-Range", "invalid if range date")
	res = checkIfRange(req, time.Now())
	assert.Equal(t, condFalse, res)
	modTime := getFileObjectModTime(time.Time{})
	assert.Empty(t, modTime)
}

func TestConnection(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "test_httpd_user",
			HomeDir:  filepath.Clean(os.TempDir()),
		},
		FsConfig: vfs.Filesystem{
			Provider: sdk.GCSFilesystemProvider,
			GCSConfig: vfs.GCSFsConfig{
				BaseGCSFsConfig: sdk.BaseGCSFsConfig{
					Bucket: "test_bucket_name",
				},
				Credentials: kms.NewPlainSecret("invalid JSON payload"),
			},
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(xid.New().String(), common.ProtocolHTTP, "", "", user),
		request:        nil,
	}
	assert.Empty(t, connection.GetClientVersion())
	assert.Empty(t, connection.GetRemoteAddress())
	assert.Empty(t, connection.GetCommand())
	name := "missing file name"
	_, err := connection.getFileReader(name, 0, http.MethodGet)
	assert.Error(t, err)
	connection.User.FsConfig.Provider = sdk.LocalFilesystemProvider
	_, err = connection.getFileReader(name, 0, http.MethodGet)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestGetFileWriterErrors(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "test_httpd_user",
			HomeDir:  "invalid",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(xid.New().String(), common.ProtocolHTTP, "", "", user),
		request:        nil,
	}
	_, err := connection.getFileWriter("name")
	assert.Error(t, err)

	user.FsConfig.Provider = sdk.S3FilesystemProvider
	user.FsConfig.S3Config = vfs.S3FsConfig{
		BaseS3FsConfig: sdk.BaseS3FsConfig{
			Bucket:    "b",
			Region:    "us-west-1",
			AccessKey: "key",
		},
		AccessSecret: kms.NewPlainSecret("secret"),
	}
	connection = &Connection{
		BaseConnection: common.NewBaseConnection(xid.New().String(), common.ProtocolHTTP, "", "", user),
		request:        nil,
	}
	_, err = connection.getFileWriter("/path")
	assert.Error(t, err)
}

func TestThrottledHandler(t *testing.T) {
	tr := &throttledReader{
		r: io.NopCloser(bytes.NewBuffer(nil)),
	}
	assert.Equal(t, int64(0), tr.GetTruncatedSize())
	err := tr.Close()
	assert.NoError(t, err)
	assert.Empty(t, tr.GetRealFsPath("real path"))
	assert.False(t, tr.SetTimes("p", time.Now(), time.Now()))
	_, err = tr.Truncate("", 0)
	assert.ErrorIs(t, err, vfs.ErrVfsUnsupported)
	err = tr.GetAbortError()
	assert.ErrorIs(t, err, common.ErrTransferAborted)
}

func TestHTTPDFile(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "test_httpd_user",
			HomeDir:  filepath.Clean(os.TempDir()),
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	connection := &Connection{
		BaseConnection: common.NewBaseConnection(xid.New().String(), common.ProtocolHTTP, "", "", user),
	}

	fs, err := user.GetFilesystem("")
	assert.NoError(t, err)

	name := "fileName"
	p := filepath.Join(os.TempDir(), name)
	err = os.WriteFile(p, []byte("contents"), os.ModePerm)
	assert.NoError(t, err)
	file, err := os.Open(p)
	assert.NoError(t, err)
	err = file.Close()
	assert.NoError(t, err)

	baseTransfer := common.NewBaseTransfer(file, connection.BaseConnection, nil, p, p, name, common.TransferDownload,
		0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	httpdFile := newHTTPDFile(baseTransfer, nil, nil)
	// the file is closed, read should fail
	buf := make([]byte, 100)
	_, err = httpdFile.Read(buf)
	assert.Error(t, err)
	err = httpdFile.Close()
	assert.Error(t, err)
	err = httpdFile.Close()
	assert.ErrorIs(t, err, common.ErrTransferClosed)
	err = os.Remove(p)
	assert.NoError(t, err)

	httpdFile.writer = file
	httpdFile.File = nil
	httpdFile.ErrTransfer = nil
	err = httpdFile.closeIO()
	assert.Error(t, err)
	assert.Error(t, httpdFile.ErrTransfer)
	assert.Equal(t, err, httpdFile.ErrTransfer)
	httpdFile.SignalClose(nil)
	_, err = httpdFile.Write(nil)
	assert.ErrorIs(t, err, common.ErrQuotaExceeded)
}

func TestChangeUserPwd(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, webChangeClientPwdPath, nil)
	err := doChangeUserPassword(req, "", "", "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "please provide the current password and the new one two times")
	}
	err = doChangeUserPassword(req, "a", "b", "c")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "the two password fields do not match")
	}
	err = doChangeUserPassword(req, "a", "b", "b")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), errInvalidTokenClaims.Error())
	}
}

func TestWebUserInvalidClaims(t *testing.T) {
	server := httpdServer{}
	server.initializeRouter()

	rr := httptest.NewRecorder()
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "",
			Password: "pwd",
		},
	}
	c := jwtTokenClaims{
		Username:    user.Username,
		Permissions: nil,
		Signature:   user.GetSignature(),
	}
	token, err := c.createTokenResponse(server.tokenAuth, tokenAudienceWebClient, "")
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientGetFiles(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientDirsPath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientGetDirContents(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorDirList403)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientDownloadZipPath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleWebClientDownloadZip(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientEditFilePath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientEditFile(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientSharePath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientAddShareGet(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientSharePath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientUpdateShareGet(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, webClientSharePath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientAddSharePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, webClientSharePath+"/id", nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientUpdateSharePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientSharesPath+jsonAPISuffix, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	getAllShares(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientViewPDFPath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientGetPDF(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)
}

func TestInvalidClaims(t *testing.T) {
	server := httpdServer{}
	server.initializeRouter()

	rr := httptest.NewRecorder()
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "",
			Password: "pwd",
		},
	}
	c := jwtTokenClaims{
		Username:    user.Username,
		Permissions: nil,
		Signature:   user.GetSignature(),
	}
	token, err := c.createTokenResponse(server.tokenAuth, tokenAudienceWebClient, "")
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, webClientProfilePath, nil)
	assert.NoError(t, err)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	parsedToken, err := jwtauth.VerifyRequest(server.tokenAuth, req, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx := req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)

	form := make(url.Values)
	form.Set(csrfFormToken, createCSRFToken(rr, req, server.csrfTokenAuth, "", webBaseClientPath))
	form.Set("public_keys", "")
	req, err = http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleWebClientProfilePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	admin := dataprovider.Admin{
		Username: "",
		Password: user.Password,
	}
	c = jwtTokenClaims{
		Username:    admin.Username,
		Permissions: nil,
		Signature:   admin.GetSignature(),
	}
	token, err = c.createTokenResponse(server.tokenAuth, tokenAudienceWebAdmin, "")
	assert.NoError(t, err)

	req, err = http.NewRequest(http.MethodGet, webAdminProfilePath, nil)
	assert.NoError(t, err)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	parsedToken, err = jwtauth.VerifyRequest(server.tokenAuth, req, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx = req.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	req = req.WithContext(ctx)

	form = make(url.Values)
	form.Set(csrfFormToken, createCSRFToken(rr, req, server.csrfTokenAuth, "", webBaseAdminPath))
	form.Set("allow_api_key_auth", "")
	req, err = http.NewRequest(http.MethodPost, webAdminProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleWebAdminProfilePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorInvalidToken)
}

func TestTLSReq(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, webClientLoginPath, nil)
	assert.NoError(t, err)
	req.TLS = &tls.ConnectionState{}
	assert.True(t, isTLS(req))
	req.TLS = nil
	ctx := context.WithValue(req.Context(), forwardedProtoKey, "https")
	assert.True(t, isTLS(req.WithContext(ctx)))
	ctx = context.WithValue(req.Context(), forwardedProtoKey, "http")
	assert.False(t, isTLS(req.WithContext(ctx)))
	assert.Equal(t, "context value forwarded proto", forwardedProtoKey.String())
}

func TestSigningKey(t *testing.T) {
	signingPassphrase := "test"
	server1 := httpdServer{
		signingPassphrase: signingPassphrase,
	}
	server1.initializeRouter()

	server2 := httpdServer{
		signingPassphrase: signingPassphrase,
	}
	server2.initializeRouter()

	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "",
			Password: "pwd",
		},
	}
	c := jwtTokenClaims{
		Username:    user.Username,
		Permissions: nil,
		Signature:   user.GetSignature(),
	}
	token, err := c.createTokenResponse(server1.tokenAuth, tokenAudienceWebClient, "")
	assert.NoError(t, err)
	accessToken := token["access_token"].(string)
	assert.NotEmpty(t, accessToken)
	_, err = server1.tokenAuth.Decode(accessToken)
	assert.NoError(t, err)
	_, err = server2.tokenAuth.Decode(accessToken)
	assert.NoError(t, err)
}

func TestLoginLinks(t *testing.T) {
	b := Binding{
		EnableWebAdmin:  true,
		EnableWebClient: false,
		EnableRESTAPI:   true,
	}
	assert.False(t, b.showClientLoginURL())
	b = Binding{
		EnableWebAdmin:  false,
		EnableWebClient: true,
		EnableRESTAPI:   true,
	}
	assert.False(t, b.showAdminLoginURL())
	b = Binding{
		EnableWebAdmin:  true,
		EnableWebClient: true,
		EnableRESTAPI:   true,
	}
	assert.True(t, b.showAdminLoginURL())
	assert.True(t, b.showClientLoginURL())
	b.HideLoginURL = 3
	assert.False(t, b.showAdminLoginURL())
	assert.False(t, b.showClientLoginURL())
	b.HideLoginURL = 1
	assert.True(t, b.showAdminLoginURL())
	assert.False(t, b.showClientLoginURL())
	b.HideLoginURL = 2
	assert.False(t, b.showAdminLoginURL())
	assert.True(t, b.showClientLoginURL())
}

func TestResetCodesCleanup(t *testing.T) {
	resetCode := newResetCode(util.GenerateUniqueID(), false)
	resetCode.ExpiresAt = time.Now().Add(-1 * time.Minute).UTC()
	err := resetCodesMgr.Add(resetCode)
	assert.NoError(t, err)
	resetCodesMgr.Cleanup()
	_, err = resetCodesMgr.Get(resetCode.Code)
	assert.Error(t, err)
}

func TestUserCanResetPassword(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, webClientLoginPath, nil)
	assert.NoError(t, err)
	req.RemoteAddr = "172.16.9.2:55080"

	u := dataprovider.User{}
	assert.True(t, isUserAllowedToResetPassword(req, &u))
	u.Filters.DeniedProtocols = []string{common.ProtocolHTTP}
	assert.False(t, isUserAllowedToResetPassword(req, &u))
	u.Filters.DeniedProtocols = nil
	u.Filters.WebClient = []string{sdk.WebClientPasswordResetDisabled}
	assert.False(t, isUserAllowedToResetPassword(req, &u))
	u.Filters.WebClient = nil
	u.Filters.DeniedLoginMethods = []string{dataprovider.LoginMethodPassword}
	assert.False(t, isUserAllowedToResetPassword(req, &u))
	u.Filters.DeniedLoginMethods = nil
	u.Filters.AllowedIP = []string{"127.0.0.1/8"}
	assert.False(t, isUserAllowedToResetPassword(req, &u))
}

func TestBrowsableSharePaths(t *testing.T) {
	share := dataprovider.Share{
		Paths:    []string{"/"},
		Username: defaultAdminUsername,
	}
	_, err := getUserForShare(share)
	if assert.Error(t, err) {
		assert.ErrorIs(t, err, util.ErrNotFound)
	}
	req, err := http.NewRequest(http.MethodGet, "/share", nil)
	require.NoError(t, err)
	name, err := getBrowsableSharedPath(share.Paths[0], req)
	assert.NoError(t, err)
	assert.Equal(t, "/", name)
	req, err = http.NewRequest(http.MethodGet, "/share?path=abc", nil)
	require.NoError(t, err)
	name, err = getBrowsableSharedPath(share.Paths[0], req)
	assert.NoError(t, err)
	assert.Equal(t, "/abc", name)

	share.Paths = []string{"/a/b/c"}
	req, err = http.NewRequest(http.MethodGet, "/share?path=abc", nil)
	require.NoError(t, err)
	name, err = getBrowsableSharedPath(share.Paths[0], req)
	assert.NoError(t, err)
	assert.Equal(t, "/a/b/c/abc", name)
	req, err = http.NewRequest(http.MethodGet, "/share?path=%2Fabc/d", nil)
	require.NoError(t, err)
	name, err = getBrowsableSharedPath(share.Paths[0], req)
	assert.NoError(t, err)
	assert.Equal(t, "/a/b/c/abc/d", name)

	req, err = http.NewRequest(http.MethodGet, "/share?path=%2Fabc%2F..%2F..", nil)
	require.NoError(t, err)
	_, err = getBrowsableSharedPath(share.Paths[0], req)
	assert.Error(t, err)

	req, err = http.NewRequest(http.MethodGet, "/share?path=%2Fabc%2F..", nil)
	require.NoError(t, err)
	name, err = getBrowsableSharedPath(share.Paths[0], req)
	assert.NoError(t, err)
	assert.Equal(t, "/a/b/c", name)

	share = dataprovider.Share{
		Paths: []string{"/a", "/b"},
	}
}

func TestSecureMiddlewareIntegration(t *testing.T) {
	forwardedHostHeader := "X-Forwarded-Host"
	server := httpdServer{
		binding: Binding{
			ProxyAllowed: []string{"192.168.1.0/24"},
			Security: SecurityConf{
				Enabled:              true,
				AllowedHosts:         []string{"*.sftpgo.com"},
				AllowedHostsAreRegex: true,
				HostsProxyHeaders:    []string{forwardedHostHeader},
				HTTPSProxyHeaders: []HTTPSProxyHeader{
					{
						Key:   xForwardedProto,
						Value: "https",
					},
				},
				STSSeconds:                31536000,
				STSIncludeSubdomains:      true,
				STSPreload:                true,
				ContentTypeNosniff:        true,
				CacheControl:              "private",
				CrossOriginOpenerPolicy:   "same-origin",
				CrossOriginResourcePolicy: "same-site",
				CrossOriginEmbedderPolicy: "require-corp",
			},
		},
		enableWebAdmin:  true,
		enableWebClient: true,
		enableRESTAPI:   true,
	}
	server.binding.Security.updateProxyHeaders()
	err := server.binding.parseAllowedProxy()
	assert.NoError(t, err)
	assert.Equal(t, []string{forwardedHostHeader, xForwardedProto}, server.binding.Security.proxyHeaders)
	assert.Equal(t, map[string]string{xForwardedProto: "https"}, server.binding.Security.getHTTPSProxyHeaders())
	server.initializeRouter()

	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, webClientLoginPath, nil)
	assert.NoError(t, err)
	r.Host = "127.0.0.1"
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "no-cache, no-store, max-age=0, must-revalidate, private", rr.Header().Get("Cache-Control"))

	rr = httptest.NewRecorder()
	r.Header.Set(forwardedHostHeader, "www.sftpgo.com")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	// the header should be removed
	assert.Empty(t, r.Header.Get(forwardedHostHeader))

	rr = httptest.NewRecorder()
	r.Host = "test.sftpgo.com"
	r.Header.Set(forwardedHostHeader, "test.example.com")
	r.RemoteAddr = "192.168.1.1"
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.NotEmpty(t, r.Header.Get(forwardedHostHeader))

	rr = httptest.NewRecorder()
	r.Header.Set(forwardedHostHeader, "www.sftpgo.com")
	r.RemoteAddr = "192.168.1.1"
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, r.Header.Get(forwardedHostHeader))
	assert.Empty(t, rr.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	// now set the X-Forwarded-Proto to https, we should get the Strict-Transport-Security header
	rr = httptest.NewRecorder()
	r.Host = "test.sftpgo.com"
	r.Header.Set(xForwardedProto, "https")
	r.RemoteAddr = "192.168.1.3"
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, r.Header.Get(forwardedHostHeader))
	assert.Equal(t, "max-age=31536000; includeSubDomains; preload", rr.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "require-corp", rr.Header().Get("Cross-Origin-Embedder-Policy"))
	assert.Equal(t, "same-origin", rr.Header().Get("Cross-Origin-Opener-Policy"))
	assert.Equal(t, "same-site", rr.Header().Get("Cross-Origin-Resource-Policy"))

	server.binding.Security.Enabled = false
	server.binding.Security.updateProxyHeaders()
	assert.Len(t, server.binding.Security.proxyHeaders, 0)
}

func TestGetCompressedFileName(t *testing.T) {
	username := "test"
	res := getCompressedFileName(username, []string{"single dir"})
	require.Equal(t, fmt.Sprintf("%s-single dir.zip", username), res)
	res = getCompressedFileName(username, []string{"file1", "file2"})
	require.Equal(t, fmt.Sprintf("%s-download.zip", username), res)
	res = getCompressedFileName(username, []string{"file1.txt"})
	require.Equal(t, fmt.Sprintf("%s-file1.zip", username), res)
	// now files with full paths
	res = getCompressedFileName(username, []string{"/dir/single dir"})
	require.Equal(t, fmt.Sprintf("%s-single dir.zip", username), res)
	res = getCompressedFileName(username, []string{"/adir/file1", "/adir/file2"})
	require.Equal(t, fmt.Sprintf("%s-download.zip", username), res)
	res = getCompressedFileName(username, []string{"/sub/dir/file1.txt"})
	require.Equal(t, fmt.Sprintf("%s-file1.zip", username), res)
}

func TestRESTAPIDisabled(t *testing.T) {
	server := httpdServer{
		enableWebAdmin:  true,
		enableWebClient: true,
		enableRESTAPI:   false,
	}
	server.initializeRouter()
	assert.False(t, server.enableRESTAPI)
	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, healthzPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)

	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, tokenPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestWebAdminSetupWithInstallCode(t *testing.T) {
	installationCode = "1234"
	// delete all the admins
	admins, err := dataprovider.GetAdmins(100, 0, dataprovider.OrderASC)
	assert.NoError(t, err)
	for _, admin := range admins {
		err = dataprovider.DeleteAdmin(admin.Username, "", "", "")
		assert.NoError(t, err)
	}
	// close the provider and initializes it without creating the default admin
	providerConf := dataprovider.GetProviderConfig()
	providerConf.CreateDefaultAdmin = false
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	server := httpdServer{
		enableWebAdmin:  true,
		enableWebClient: true,
		enableRESTAPI:   true,
	}
	server.initializeRouter()

	for _, webURL := range []string{"/", webBasePath, webBaseAdminPath, webAdminLoginPath, webClientLoginPath} {
		rr := httptest.NewRecorder()
		r, err := http.NewRequest(http.MethodGet, webURL, nil)
		assert.NoError(t, err)
		server.router.ServeHTTP(rr, r)
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, webAdminSetupPath, rr.Header().Get("Location"))
	}

	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, webAdminSetupPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	cookie := rr.Header().Get("Set-Cookie")
	r.Header.Set("Cookie", cookie)
	parsedToken, err := jwtauth.VerifyRequest(server.csrfTokenAuth, r, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx := r.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	r = r.WithContext(ctx)

	form := make(url.Values)
	csrfToken := createCSRFToken(rr, r, server.csrfTokenAuth, "", webBaseAdminPath)
	form.Set(csrfFormToken, csrfToken)
	form.Set("install_code", installationCode+"5")
	form.Set("username", defaultAdminUsername)
	form.Set("password", "password")
	form.Set("confirm_password", "password")
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	r = r.WithContext(ctx)
	r.Header.Set("Cookie", cookie)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorSetupInstallCode)

	_, err = dataprovider.AdminExists(defaultAdminUsername)
	assert.Error(t, err)
	form.Set("install_code", installationCode)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	r = r.WithContext(ctx)
	r.Header.Set("Cookie", cookie)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminMFAPath, rr.Header().Get("Location"))

	_, err = dataprovider.AdminExists(defaultAdminUsername)
	assert.NoError(t, err)

	// delete the admin and test the installation code resolver
	err = dataprovider.DeleteAdmin(defaultAdminUsername, "", "", "")
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	SetInstallationCodeResolver(func(_ string) string {
		return "5678"
	})

	for _, webURL := range []string{"/", webBasePath, webBaseAdminPath, webAdminLoginPath, webClientLoginPath} {
		rr = httptest.NewRecorder()
		r, err = http.NewRequest(http.MethodGet, webURL, nil)
		assert.NoError(t, err)
		server.router.ServeHTTP(rr, r)
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, webAdminSetupPath, rr.Header().Get("Location"))
	}

	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webAdminSetupPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	cookie = rr.Header().Get("Set-Cookie")
	r.Header.Set("Cookie", cookie)
	parsedToken, err = jwtauth.VerifyRequest(server.csrfTokenAuth, r, jwtauth.TokenFromCookie)
	assert.NoError(t, err)
	ctx = r.Context()
	ctx = jwtauth.NewContext(ctx, parsedToken, err)
	r = r.WithContext(ctx)

	form = make(url.Values)
	csrfToken = createCSRFToken(rr, r, server.csrfTokenAuth, "", webBaseAdminPath)
	form.Set(csrfFormToken, csrfToken)
	form.Set("install_code", installationCode)
	form.Set("username", defaultAdminUsername)
	form.Set("password", "password")
	form.Set("confirm_password", "password")
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	r = r.WithContext(ctx)
	r.Header.Set("Cookie", cookie)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), util.I18nErrorSetupInstallCode)

	_, err = dataprovider.AdminExists(defaultAdminUsername)
	assert.Error(t, err)
	form.Set("install_code", "5678")
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	r = r.WithContext(ctx)
	r.Header.Set("Cookie", cookie)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminMFAPath, rr.Header().Get("Location"))

	_, err = dataprovider.AdminExists(defaultAdminUsername)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	providerConf.CreateDefaultAdmin = true
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	installationCode = ""
	SetInstallationCodeResolver(nil)
}

func TestDbResetCodeManager(t *testing.T) {
	if !isSharedProviderSupported() {
		t.Skip("this test it is not available with this provider")
	}
	mgr := newResetCodeManager(1)
	resetCode := newResetCode("admin", true)
	err := mgr.Add(resetCode)
	assert.NoError(t, err)
	codeGet, err := mgr.Get(resetCode.Code)
	assert.NoError(t, err)
	assert.Equal(t, resetCode, codeGet)
	err = mgr.Delete(resetCode.Code)
	assert.NoError(t, err)
	err = mgr.Delete(resetCode.Code)
	if assert.Error(t, err) {
		assert.ErrorIs(t, err, util.ErrNotFound)
	}
	_, err = mgr.Get(resetCode.Code)
	assert.ErrorIs(t, err, util.ErrNotFound)
	// add an expired reset code
	resetCode = newResetCode("user", false)
	resetCode.ExpiresAt = time.Now().Add(-24 * time.Hour)
	err = mgr.Add(resetCode)
	assert.NoError(t, err)
	_, err = mgr.Get(resetCode.Code)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "reset code expired")
	}
	mgr.Cleanup()
	_, err = mgr.Get(resetCode.Code)
	assert.ErrorIs(t, err, util.ErrNotFound)

	dbMgr, ok := mgr.(*dbResetCodeManager)
	if assert.True(t, ok) {
		_, err = dbMgr.decodeData("astring")
		assert.Error(t, err)
	}
}

func TestDecodeToken(t *testing.T) {
	nodeID := "nodeID"
	token := map[string]any{
		claimUsernameKey:            defaultAdminUsername,
		claimPermissionsKey:         []string{dataprovider.PermAdminAny},
		jwt.SubjectKey:              "",
		claimNodeID:                 nodeID,
		claimMustChangePasswordKey:  false,
		claimMustSetSecondFactorKey: true,
		claimRef:                    "ref",
	}
	c := jwtTokenClaims{}
	c.Decode(token)
	assert.Equal(t, defaultAdminUsername, c.Username)
	assert.Equal(t, nodeID, c.NodeID)
	assert.False(t, c.MustChangePassword)
	assert.True(t, c.MustSetTwoFactorAuth)
	assert.Equal(t, "ref", c.Ref)

	asMap := c.asMap()
	asMap[claimMustChangePasswordKey] = false
	assert.Equal(t, token, asMap)

	token[claimMustChangePasswordKey] = 10
	c = jwtTokenClaims{}
	c.Decode(token)
	assert.False(t, c.MustChangePassword)

	token[claimMustChangePasswordKey] = true
	c = jwtTokenClaims{}
	c.Decode(token)
	assert.True(t, c.MustChangePassword)

	claims := c.asMap()
	assert.Equal(t, token, claims)
}

func TestEventRoleFilter(t *testing.T) {
	defaultVal := "default"
	req, err := http.NewRequest(http.MethodGet, fsEventsPath+"?role=role1", nil)
	require.NoError(t, err)
	role := getRoleFilterForEventSearch(req, defaultVal)
	assert.Equal(t, defaultVal, role)
	role = getRoleFilterForEventSearch(req, "")
	assert.Equal(t, "role1", role)
}

func TestEventsCSV(t *testing.T) {
	e := fsEvent{
		Status: 1,
	}
	data := e.getCSVData()
	assert.Equal(t, "OK", data[5])
	e.Status = 2
	data = e.getCSVData()
	assert.Equal(t, "KO", data[5])
	e.Status = 3
	data = e.getCSVData()
	assert.Equal(t, "Quota exceeded", data[5])
}

func TestConfigsFromProvider(t *testing.T) {
	err := dataprovider.UpdateConfigs(nil, "", "", "")
	assert.NoError(t, err)
	c := Conf{
		Bindings: []Binding{
			{
				Port: 1234,
			},
			{
				Port: 80,
				Security: SecurityConf{
					Enabled:       true,
					HTTPSRedirect: true,
				},
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
			Protocols:       1,
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
	assert.False(t, c.Bindings[1].EnableHTTPS)
	// protocols does not match
	configs.ACME.Protocols = 6
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

func TestHTTPSRedirect(t *testing.T) {
	acmeWebRoot := filepath.Join(os.TempDir(), "acme")
	err := os.MkdirAll(acmeWebRoot, os.ModePerm)
	assert.NoError(t, err)
	tokenName := "token"
	err = os.WriteFile(filepath.Join(acmeWebRoot, tokenName), []byte("val"), 0666)
	assert.NoError(t, err)

	acmeConfig := acme.Configuration{
		HTTP01Challenge: acme.HTTP01Challenge{WebRoot: acmeWebRoot},
	}
	err = acme.Initialize(acmeConfig, configDir, true)
	require.NoError(t, err)

	forwardedHostHeader := "X-Forwarded-Host"
	server := httpdServer{
		binding: Binding{
			Security: SecurityConf{
				Enabled:           true,
				HTTPSRedirect:     true,
				HostsProxyHeaders: []string{forwardedHostHeader},
			},
		},
	}
	server.initializeRouter()

	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, path.Join(acmeChallengeURI, tokenName), nil)
	assert.NoError(t, err)
	r.Host = "localhost"
	r.RequestURI = path.Join(acmeChallengeURI, tokenName)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webAdminLoginPath, nil)
	assert.NoError(t, err)
	r.RequestURI = webAdminLoginPath
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusTemporaryRedirect, rr.Code, rr.Body.String())

	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webAdminLoginPath, nil)
	assert.NoError(t, err)
	r.RequestURI = webAdminLoginPath
	r.Header.Set(forwardedHostHeader, "sftpgo.com")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusTemporaryRedirect, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "https://sftpgo.com")

	server.binding.Security.HTTPSHost = "myhost:1044"
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webAdminLoginPath, nil)
	assert.NoError(t, err)
	r.RequestURI = webAdminLoginPath
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusTemporaryRedirect, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "https://myhost:1044")

	err = os.RemoveAll(acmeWebRoot)
	assert.NoError(t, err)
}

func TestDisabledAdminLoginMethods(t *testing.T) {
	server := httpdServer{
		binding: Binding{
			Address:              "",
			Port:                 8080,
			EnableWebAdmin:       true,
			EnableWebClient:      true,
			EnableRESTAPI:        true,
			DisabledLoginMethods: 20,
		},
		enableWebAdmin:  true,
		enableWebClient: true,
		enableRESTAPI:   true,
	}
	server.initializeRouter()
	testServer := httptest.NewServer(server.router)
	defer testServer.Close()

	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, tokenPath, nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, path.Join(adminPath, defaultAdminUsername, "forgot-password"), nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, path.Join(adminPath, defaultAdminUsername, "reset-password"), nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, webAdminLoginPath, nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, webAdminResetPwdPath, nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, webAdminForgotPwdPath, nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestDisabledUserLoginMethods(t *testing.T) {
	server := httpdServer{
		binding: Binding{
			Address:              "",
			Port:                 8080,
			EnableWebAdmin:       true,
			EnableWebClient:      true,
			EnableRESTAPI:        true,
			DisabledLoginMethods: 40,
		},
		enableWebAdmin:  true,
		enableWebClient: true,
		enableRESTAPI:   true,
	}
	server.initializeRouter()
	testServer := httptest.NewServer(server.router)
	defer testServer.Close()

	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, userTokenPath, nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, userPath+"/user/forgot-password", nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, userPath+"/user/reset-password", nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, webClientLoginPath, nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, webClientResetPwdPath, nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, webClientForgotPwdPath, nil)
	require.NoError(t, err)
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGetLogEventString(t *testing.T) {
	assert.Equal(t, "Login failed", getLogEventString(notifier.LogEventTypeLoginFailed))
	assert.Equal(t, "Login with non-existent user", getLogEventString(notifier.LogEventTypeLoginNoUser))
	assert.Equal(t, "No login tried", getLogEventString(notifier.LogEventTypeNoLoginTried))
	assert.Equal(t, "Algorithm negotiation failed", getLogEventString(notifier.LogEventTypeNotNegotiated))
	assert.Equal(t, "Login succeeded", getLogEventString(notifier.LogEventTypeLoginOK))
	assert.Empty(t, getLogEventString(0))
}

func TestUserQuotaUsage(t *testing.T) {
	usage := userQuotaUsage{
		QuotaSize: 100,
	}
	require.True(t, usage.HasQuotaInfo())
	require.NotEmpty(t, usage.GetQuotaSize())
	providerConf := dataprovider.GetProviderConfig()
	quotaTracking := dataprovider.GetQuotaTracking()
	providerConf.TrackQuota = 0
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	assert.False(t, usage.HasQuotaInfo())
	providerConf.TrackQuota = quotaTracking
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	usage.QuotaSize = 0
	assert.False(t, usage.HasQuotaInfo())
	assert.Empty(t, usage.GetQuotaSize())
	assert.Equal(t, 0, usage.GetQuotaSizePercentage())
	assert.False(t, usage.IsQuotaSizeLow())
	assert.False(t, usage.IsDiskQuotaLow())
	assert.False(t, usage.IsQuotaLow())
	usage.UsedQuotaSize = 9
	assert.NotEmpty(t, usage.GetQuotaSize())
	usage.QuotaSize = 10
	assert.True(t, usage.IsQuotaSizeLow())
	assert.True(t, usage.IsDiskQuotaLow())
	assert.True(t, usage.IsQuotaLow())
	usage.DownloadDataTransfer = 1
	assert.True(t, usage.HasQuotaInfo())
	assert.True(t, usage.HasTranferQuota())
	assert.Empty(t, usage.GetQuotaFiles())
	assert.Equal(t, 0, usage.GetQuotaFilesPercentage())
	usage.QuotaFiles = 1
	assert.NotEmpty(t, usage.GetQuotaFiles())
	usage.QuotaFiles = 0
	usage.UsedQuotaFiles = 9
	assert.NotEmpty(t, usage.GetQuotaFiles())
	usage.QuotaFiles = 10
	usage.DownloadDataTransfer = 0
	assert.True(t, usage.IsQuotaFilesLow())
	assert.True(t, usage.IsDiskQuotaLow())
	assert.False(t, usage.IsTotalTransferQuotaLow())
	assert.False(t, usage.IsUploadTransferQuotaLow())
	assert.False(t, usage.IsDownloadTransferQuotaLow())
	assert.Equal(t, 0, usage.GetTotalTransferQuotaPercentage())
	assert.Equal(t, 0, usage.GetUploadTransferQuotaPercentage())
	assert.Equal(t, 0, usage.GetDownloadTransferQuotaPercentage())
	assert.Empty(t, usage.GetTotalTransferQuota())
	assert.Empty(t, usage.GetUploadTransferQuota())
	assert.Empty(t, usage.GetDownloadTransferQuota())
	usage.TotalDataTransfer = 3
	usage.UsedUploadDataTransfer = 1 * 1048576
	assert.NotEmpty(t, usage.GetTotalTransferQuota())
	usage.TotalDataTransfer = 0
	assert.NotEmpty(t, usage.GetTotalTransferQuota())
	assert.NotEmpty(t, usage.GetUploadTransferQuota())
	usage.UploadDataTransfer = 2
	assert.NotEmpty(t, usage.GetUploadTransferQuota())
	usage.UsedDownloadDataTransfer = 1 * 1048576
	assert.NotEmpty(t, usage.GetDownloadTransferQuota())
	usage.DownloadDataTransfer = 2
	assert.NotEmpty(t, usage.GetDownloadTransferQuota())
	assert.False(t, usage.IsTransferQuotaLow())
	usage.UsedDownloadDataTransfer = 8 * 1048576
	usage.TotalDataTransfer = 10
	assert.True(t, usage.IsTotalTransferQuotaLow())
	assert.True(t, usage.IsTransferQuotaLow())
	usage.TotalDataTransfer = 0
	usage.UploadDataTransfer = 0
	usage.DownloadDataTransfer = 0
	assert.False(t, usage.IsTransferQuotaLow())
	usage.UploadDataTransfer = 10
	usage.UsedUploadDataTransfer = 9 * 1048576
	assert.True(t, usage.IsUploadTransferQuotaLow())
	assert.True(t, usage.IsTransferQuotaLow())
	usage.DownloadDataTransfer = 10
	usage.UsedDownloadDataTransfer = 9 * 1048576
	assert.True(t, usage.IsDownloadTransferQuotaLow())
	assert.True(t, usage.IsTransferQuotaLow())
}

func TestShareRedirectURL(t *testing.T) {
	shareID := util.GenerateUniqueID()
	base := path.Join(webClientPubSharesPath, shareID)
	next := path.Join(webClientPubSharesPath, shareID, "browse")
	ok, res := checkShareRedirectURL(next, base)
	assert.True(t, ok)
	assert.Equal(t, next, res)
	next = path.Join(webClientPubSharesPath, shareID, "browse") + "?a=b"
	ok, res = checkShareRedirectURL(next, base)
	assert.True(t, ok)
	assert.Equal(t, next, res)
	next = path.Join(webClientPubSharesPath, shareID)
	ok, res = checkShareRedirectURL(next, base)
	assert.True(t, ok)
	assert.Equal(t, path.Join(base, "download"), res)
	next = path.Join(webClientEditFilePath, shareID)
	ok, res = checkShareRedirectURL(next, base)
	assert.False(t, ok)
	assert.Empty(t, res)
	next = path.Join(webClientPubSharesPath, shareID) + "?compress=false&a=b"
	ok, res = checkShareRedirectURL(next, base)
	assert.True(t, ok)
	assert.Equal(t, path.Join(base, "download?compress=false&a=b"), res)
	next = path.Join(webClientPubSharesPath, shareID) + "?compress=true&b=c"
	ok, res = checkShareRedirectURL(next, base)
	assert.True(t, ok)
	assert.Equal(t, path.Join(base, "download?compress=true&b=c"), res)
	ok, res = checkShareRedirectURL("http://foo\x7f.com/ab", "http://foo\x7f.com/")
	assert.False(t, ok)
	assert.Empty(t, res)
	ok, res = checkShareRedirectURL("http://foo.com/?foo\nbar", "http://foo.com")
	assert.False(t, ok)
	assert.Empty(t, res)
}

func TestI18NMessages(t *testing.T) {
	msg := i18nListDirMsg(http.StatusForbidden)
	require.Equal(t, util.I18nErrorDirList403, msg)
	msg = i18nListDirMsg(http.StatusInternalServerError)
	require.Equal(t, util.I18nErrorDirListGeneric, msg)
	msg = i18nFsMsg(http.StatusForbidden)
	require.Equal(t, util.I18nError403Message, msg)
	msg = i18nFsMsg(http.StatusInternalServerError)
	require.Equal(t, util.I18nErrorFsGeneric, msg)
}

func TestI18NErrors(t *testing.T) {
	err := util.NewValidationError("error text")
	errI18n := util.NewI18nError(err, util.I18nError500Message)
	assert.ErrorIs(t, errI18n, util.ErrValidation)
	assert.Equal(t, err.Error(), errI18n.Error())
	assert.Equal(t, util.I18nError500Message, getI18NErrorString(errI18n, ""))
	assert.Equal(t, util.I18nError500Message, errI18n.Message)
	assert.Equal(t, "{}", errI18n.Args())
	var e1 *util.ValidationError
	assert.ErrorAs(t, errI18n, &e1)
	var e2 *util.I18nError
	assert.ErrorAs(t, errI18n, &e2)
	err2 := util.NewI18nError(fs.ErrNotExist, util.I18nError500Message)
	assert.ErrorIs(t, err2, &util.I18nError{})
	assert.ErrorIs(t, err2, fs.ErrNotExist)
	assert.NotErrorIs(t, err2, fs.ErrExist)
	assert.Equal(t, util.I18nError403Message, getI18NErrorString(fs.ErrClosed, util.I18nError403Message))
	errorString := getI18NErrorString(nil, util.I18nError500Message)
	assert.Equal(t, util.I18nError500Message, errorString)
	errI18nWrap := util.NewI18nError(errI18n, util.I18nError404Message)
	assert.Equal(t, util.I18nError500Message, errI18nWrap.Message)
	errI18n = util.NewI18nError(err, util.I18nError500Message, util.I18nErrorArgs(map[string]any{"a": "b"}))
	assert.Equal(t, util.I18nError500Message, errI18n.Message)
	assert.Equal(t, `{"a":"b"}`, errI18n.Args())
}

func TestConvertEnabledLoginMethods(t *testing.T) {
	b := Binding{
		EnabledLoginMethods:  0,
		DisabledLoginMethods: 1,
	}
	b.convertLoginMethods()
	assert.Equal(t, 1, b.DisabledLoginMethods)
	b.DisabledLoginMethods = 0
	b.EnabledLoginMethods = 1
	b.convertLoginMethods()
	assert.Equal(t, 14, b.DisabledLoginMethods)
	b.DisabledLoginMethods = 0
	b.EnabledLoginMethods = 2
	b.convertLoginMethods()
	assert.Equal(t, 13, b.DisabledLoginMethods)
	b.DisabledLoginMethods = 0
	b.EnabledLoginMethods = 3
	b.convertLoginMethods()
	assert.Equal(t, 12, b.DisabledLoginMethods)
	b.DisabledLoginMethods = 0
	b.EnabledLoginMethods = 4
	b.convertLoginMethods()
	assert.Equal(t, 11, b.DisabledLoginMethods)
	b.DisabledLoginMethods = 0
	b.EnabledLoginMethods = 7
	b.convertLoginMethods()
	assert.Equal(t, 8, b.DisabledLoginMethods)
	b.DisabledLoginMethods = 0
	b.EnabledLoginMethods = 15
	b.convertLoginMethods()
	assert.Equal(t, 0, b.DisabledLoginMethods)
}

func getCSRFTokenFromBody(body io.Reader) (string, error) {
	doc, err := html.Parse(body)
	if err != nil {
		return "", err
	}

	var csrfToken string
	var f func(*html.Node)

	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			for _, attr := range n.Attr {
				if attr.Key == "value" {
					value = attr.Val
				}
				if attr.Key == "name" {
					name = attr.Val
				}
			}
			if name == csrfFormToken {
				csrfToken = value
				return
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}

	f(doc)

	if csrfToken == "" {
		return "", errors.New("CSRF token not found")
	}

	return csrfToken, nil
}

func isSharedProviderSupported() bool {
	// SQLite shares the implementation with other SQL-based provider but it makes no sense
	// to use it outside test cases
	switch dataprovider.GetProviderStatus().Driver {
	case dataprovider.MySQLDataProviderName, dataprovider.PGSQLDataProviderName,
		dataprovider.CockroachDataProviderName, dataprovider.SQLiteDataProviderName:
		return true
	default:
		return false
	}
}
