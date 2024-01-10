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

package common

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	serverCert = `-----BEGIN CERTIFICATE-----
MIIEIjCCAgqgAwIBAgIQfxHX0pnvRtkmtfLklgrcNzANBgkqhkiG9w0BAQsFADAT
MREwDwYDVQQDEwhDZXJ0QXV0aDAeFw0yMzAxMDMxMDIyMDdaFw0zMzAxMDMxMDMw
NDVaMBQxEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAKbMWjMhyjMnDsq/19J9D44Y13uPSMN26NFOCfjVgV23zcqvI8W1
csosYj89gSmIRxpcL2FtX7NjIT4vaqXob/en1lYy8hstacOs2cy2LcVZHfxu/hv3
6hEKLY28tOD41L1CYZesBt3yV8vGcYIOnnAdIiG52SChnduTafBVE9Pq5P7qJ1gZ
d4uBYxe8/Za0metKDvMN6FTK+THq56eD830iRwFOdSw3Z4NS/nQNeVW263E4CC4u
BVxgwIHu6giqEfIoV6oVTY64y8X2YlwqvbVN/OtWNIJBLu+mN2EhR2ygpZdAyc82
1yrk/X2/Dd3OiKSrrvXL1fOuNGlLNGD+3vUCAwEAAaNxMG8wDgYDVR0PAQH/BAQD
AgO4MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUabrE
6ATHRqEf/CDQiNWI+0e/nhIwHwYDVR0jBBgwFoAUKPyWZxHuWgH3MA/996i3V4gd
aYgwDQYJKoZIhvcNAQELBQADggIBAHFtnPXxCCeeGw4RiIai3bavGtyK5qooZUia
hN8abJp9VJKYthLwF75c0wn8W0ZMTY8z9xgmFK9afWHCBNyK+0KCpd/LdDUfwvIn
3RwR4HRFjNG+n1UZBA4l1W6X6kCq9/x7YaKLrek9aBHfxwMnoMrOeMUybm6D+B5E
lSkAyJRq5VHVatM7UGmdux2MXK5IMpzlIBzz1pXddnzF3f9nfS54xt6ilWst9bMi
6mBxisJmqc51L/Fyb2SoCJoO/6kv+3V5HnRNBcZuVE8G5/Uc+WRnyy9dh996W83b
jNvSJ9UpspqMtKx7DKU4fC/3xYDjRimZvZ3akfIdkf3j5GVWMtVbx+QVSZ8aKBSM
Zx35p8aF0zppTjp2JvBpiQlGIXKfPkmmH4bLpU7Z7qLXFFnp+fs3CjcIng19gGgi
XQldgHVsl8FtIebxgW6wc5jb2y/fXjgx9c0SKEeeA3Pp6fExH8PdQdyHHmkHKQzO
ozon1tZhQbcjkNz8kXFp3x3X/0i4TsR6vsUigSFHXT7DgusBK8eAiRVOLSpbfIyp
7Ul/9DjhtYxcZjNI/xNJcECPGazNDdKh4TdLh35pnQHOsRXDWB873rr5xkJIUXbU
ubo+q0VpmF7OtfPO9PrPilWAUhVDRx7CCTW3YUsWrYJkr8d6F/n6y7QPKMtB9Y2P
jRJ4LDqX
-----END CERTIFICATE-----`
	serverKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEApsxaMyHKMycOyr/X0n0PjhjXe49Iw3bo0U4J+NWBXbfNyq8j
xbVyyixiPz2BKYhHGlwvYW1fs2MhPi9qpehv96fWVjLyGy1pw6zZzLYtxVkd/G7+
G/fqEQotjby04PjUvUJhl6wG3fJXy8Zxgg6ecB0iIbnZIKGd25Np8FUT0+rk/uon
WBl3i4FjF7z9lrSZ60oO8w3oVMr5Mernp4PzfSJHAU51LDdng1L+dA15VbbrcTgI
Li4FXGDAge7qCKoR8ihXqhVNjrjLxfZiXCq9tU3861Y0gkEu76Y3YSFHbKCll0DJ
zzbXKuT9fb8N3c6IpKuu9cvV8640aUs0YP7e9QIDAQABAoIBADbD9gG/4HH3KwYr
AyPbaBYR1f59xzhWfI7sfp2zDGzHAsy/wJETyILVG9UDzrriQeZHyk7E6J0vuSR/
0RZ0QP8hnmBjDdcajBVxVXm/fzvCzPOrRcfNGI9LtjVJdmI/kSoq93wjQYXyIh2I
JJC9WAwbpK9KJB5wsjH8LtZ4OLBlcdeB8jcvO6FzGij6HwyxqyPctxetlvpcmc/w
zNJhps6t+TJ8PpNtEmTpOOmx85V6HMb3QJexwmUYygRaOoiQKBKZSNaOnGoC8w1d
WahyyXJk4B3OUllqG1TLUgabFGqq2PeJSP8RvYFH8DUj+fdxD78qDHAygrL8ELLZ
2O3Wi0ECgYEAyREnS/kylyIcAsyKczsKEDMIDUF9rGvm2B+QG7cLKHTu24oiNg5B
Ik5nkaYmSSrC3O2/s4v47mYzMtWbLxlogiNK6ljLPpdU5/JaeHncZC+18seBoePQ
9nOW3AvY2A6ihzy8sKRMfl3FUx/1rcXLdNwkMQo0FWR7nqVPUme9QkkCgYEA1F5n
lhfDptiHekagKMTf9SGw4B2UiG6SLjMWhcG2AEFeXpZlsk7Qubnuzk0krjYp+JAI
brlzMOkmBXBQywKLe3SG0s0McbRGWVFbEA1SA+WZV5rwJe5PO7W6ndCF2+slyZ5T
dPwOY1RybV6R07EvjtfnE8Wtdyko4X22sTkyd00CgYA5MYnuEHqVhvxUx33yfS7F
oN5/dsuayi6l94R0fcLMxUZUaJyGp9NbQNYxFgP5+BHp6i8HkZ9DoQqbQSudYCrc
KdHbi1p0+XMLb2LQtkk8rl2hK6LyO+1qzUJyYWRTQQZ2VY6O6I1hvKaumH636XWQ
TjZ1RKPAGg8X94nytNOfEQKBgQC/+TL0iDjyGyykyTFAiW/WXQVSIwtBJYr5Pm9u
rESFCJJxOM1nmT2vlrecQDoXTZk1O6aTyQqrPSeEpRoz2fISwKyb5IYKRyeM2DFU
WmY4ZZXvjnzmHP39APNYc8Z9nZzEHF5fEvdCrXTfDy0Ny08tdlhKFFkRreBprkW3
APhwxQKBgDBdionnjdB9jdGbYHrsPaweMGdQNXkrTTCFfBA47F+qZswfon12yu4A
+cBKCnQe2dQHl8AV3IeUKpmNghu4iICOASQEO9dS6OWZI5vBxZMePBm6+bjTOuf6
ozecw3yR55tKpPImt87rhrWlwp35uWuhOr9GHYBdFSwgrEkVMw++
-----END RSA PRIVATE KEY-----`
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

func TestLoadCertificate(t *testing.T) {
	startEventScheduler()
	caCrtPath := filepath.Join(os.TempDir(), "testca.crt")
	caCrlPath := filepath.Join(os.TempDir(), "testcrl.crt")
	certPath := filepath.Join(os.TempDir(), "test.crt")
	keyPath := filepath.Join(os.TempDir(), "test.key")
	err := os.WriteFile(caCrtPath, []byte(caCRT), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(caCrlPath, []byte(caCRL), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(certPath, []byte(serverCert), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(serverKey), os.ModePerm)
	assert.NoError(t, err)
	keyPairs := []TLSKeyPair{
		{
			Cert: certPath,
			Key:  keyPath,
			ID:   DefaultTLSKeyPaidID,
		},
		{
			Cert: certPath,
			Key:  keyPath,
			ID:   DefaultTLSKeyPaidID,
		},
	}
	certManager, err := NewCertManager(keyPairs, configDir, logSenderTest)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is duplicated")
	}
	assert.Nil(t, certManager)

	keyPairs = []TLSKeyPair{
		{
			Cert: certPath,
			Key:  keyPath,
			ID:   DefaultTLSKeyPaidID,
		},
	}

	certManager, err = NewCertManager(keyPairs, configDir, logSenderTest)
	assert.NoError(t, err)
	assert.True(t, certManager.HasCertificate(DefaultTLSKeyPaidID))
	assert.False(t, certManager.HasCertificate("unknownID"))
	certFunc := certManager.GetCertificateFunc(DefaultTLSKeyPaidID)
	if assert.NotNil(t, certFunc) {
		hello := &tls.ClientHelloInfo{
			ServerName:   "localhost",
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
		}
		cert, err := certFunc(hello)
		assert.NoError(t, err)
		assert.Equal(t, certManager.certs[DefaultTLSKeyPaidID], cert)
	}
	certFunc = certManager.GetCertificateFunc("unknownID")
	if assert.NotNil(t, certFunc) {
		hello := &tls.ClientHelloInfo{
			ServerName:   "localhost",
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
		}
		_, err = certFunc(hello)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "no certificate for id unknownID")
		}
	}
	certManager.SetCACertificates(nil)
	err = certManager.LoadRootCAs()
	assert.NoError(t, err)

	certManager.SetCACertificates([]string{""})
	err = certManager.LoadRootCAs()
	assert.Error(t, err)

	certManager.SetCACertificates([]string{"invalid"})
	err = certManager.LoadRootCAs()
	assert.Error(t, err)

	// laoding the key as root CA must fail
	certManager.SetCACertificates([]string{keyPath})
	err = certManager.LoadRootCAs()
	assert.Error(t, err)

	certManager.SetCACertificates([]string{certPath})
	err = certManager.LoadRootCAs()
	assert.NoError(t, err)

	rootCa := certManager.GetRootCAs()
	assert.NotNil(t, rootCa)

	err = certManager.Reload()
	assert.NoError(t, err)

	certManager.SetCARevocationLists(nil)
	err = certManager.LoadCRLs()
	assert.NoError(t, err)

	certManager.SetCARevocationLists([]string{""})
	err = certManager.LoadCRLs()
	assert.Error(t, err)

	certManager.SetCARevocationLists([]string{"invalid crl"})
	err = certManager.LoadCRLs()
	assert.Error(t, err)

	// this is not a crl and must fail
	certManager.SetCARevocationLists([]string{caCrtPath})
	err = certManager.LoadCRLs()
	assert.Error(t, err)

	certManager.SetCARevocationLists([]string{caCrlPath})
	err = certManager.LoadCRLs()
	assert.NoError(t, err)

	crt, err := tls.X509KeyPair([]byte(caCRT), []byte(caKey))
	assert.NoError(t, err)

	x509CAcrt, err := x509.ParseCertificate(crt.Certificate[0])
	assert.NoError(t, err)

	crt, err = tls.X509KeyPair([]byte(client1Crt), []byte(client1Key))
	assert.NoError(t, err)
	x509crt, err := x509.ParseCertificate(crt.Certificate[0])
	if assert.NoError(t, err) {
		assert.False(t, certManager.IsRevoked(x509crt, x509CAcrt))
	}

	crt, err = tls.X509KeyPair([]byte(client2Crt), []byte(client2Key))
	assert.NoError(t, err)
	x509crt, err = x509.ParseCertificate(crt.Certificate[0])
	if assert.NoError(t, err) {
		assert.True(t, certManager.IsRevoked(x509crt, x509CAcrt))
	}

	assert.True(t, certManager.IsRevoked(nil, nil))

	err = os.Remove(caCrlPath)
	assert.NoError(t, err)
	err = certManager.Reload()
	assert.Error(t, err)

	err = os.Remove(certPath)
	assert.NoError(t, err)
	err = os.Remove(keyPath)
	assert.NoError(t, err)
	err = certManager.Reload()
	assert.Error(t, err)

	err = os.Remove(caCrtPath)
	assert.NoError(t, err)
	stopEventScheduler()
}

func TestLoadInvalidCert(t *testing.T) {
	startEventScheduler()
	certManager, err := NewCertManager(nil, configDir, logSenderTest)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no key pairs defined")
	}
	assert.Nil(t, certManager)

	keyPairs := []TLSKeyPair{
		{
			Cert: "test.crt",
			Key:  "test.key",
			ID:   DefaultTLSKeyPaidID,
		},
	}
	certManager, err = NewCertManager(keyPairs, configDir, logSenderTest)
	assert.Error(t, err)
	assert.Nil(t, certManager)

	keyPairs = []TLSKeyPair{
		{
			Cert: "test.crt",
			Key:  "test.key",
		},
	}
	certManager, err = NewCertManager(keyPairs, configDir, logSenderTest)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "TLS certificate without ID")
	}
	assert.Nil(t, certManager)
	stopEventScheduler()
}

func TestCertificateMonitor(t *testing.T) {
	startEventScheduler()
	defer stopEventScheduler()

	certPath := filepath.Join(os.TempDir(), "test.crt")
	keyPath := filepath.Join(os.TempDir(), "test.key")
	caCrlPath := filepath.Join(os.TempDir(), "testcrl.crt")
	err := os.WriteFile(certPath, []byte(serverCert), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(keyPath, []byte(serverKey), os.ModePerm)
	assert.NoError(t, err)
	err = os.WriteFile(caCrlPath, []byte(caCRL), os.ModePerm)
	assert.NoError(t, err)

	keyPairs := []TLSKeyPair{
		{
			Cert: certPath,
			Key:  keyPath,
			ID:   DefaultTLSKeyPaidID,
		},
	}
	certManager, err := NewCertManager(keyPairs, configDir, logSenderTest)
	assert.NoError(t, err)
	assert.Len(t, certManager.monitorList, 1)
	require.Len(t, certManager.certsInfo, 1)
	info := certManager.certsInfo[certPath]
	require.NotNil(t, info)
	certManager.SetCARevocationLists([]string{caCrlPath})
	err = certManager.LoadCRLs()
	assert.NoError(t, err)
	assert.Len(t, certManager.monitorList, 2)
	certManager.monitor()
	require.Len(t, certManager.certsInfo, 2)

	err = os.Remove(certPath)
	assert.NoError(t, err)
	certManager.monitor()

	time.Sleep(100 * time.Millisecond)
	err = os.WriteFile(certPath, []byte(serverCert), os.ModePerm)
	assert.NoError(t, err)
	certManager.monitor()
	require.Len(t, certManager.certsInfo, 2)
	newInfo := certManager.certsInfo[certPath]
	require.NotNil(t, newInfo)
	assert.Equal(t, info.Size(), newInfo.Size())
	assert.NotEqual(t, info.ModTime(), newInfo.ModTime())

	err = os.Remove(caCrlPath)
	assert.NoError(t, err)

	err = os.Remove(certPath)
	assert.NoError(t, err)
	err = os.Remove(keyPath)
	assert.NoError(t, err)
}
