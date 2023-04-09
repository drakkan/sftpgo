// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
QXV0aDAeFw0yMzAxMDMxMDIwNDdaFw0zMzAxMDMxMDMwNDZaMBMxETAPBgNVBAMT
CENlcnRBdXRoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxq6Wl1Ih
hgvGdM8M2IVI7dwnv3yShJygZsnREQSEW0xeWJL5DtNeHCME5WByFUAlZKpePtW8
TNwln9DYDtgNSMiWwvO/wR0mXsyU8Ma4ZBMlX0oOkWo1Ff/M/u8YY9X78Vvwdt62
Yt7QmU5oUUW2HdAgh4AlhKJSjm3t0uDP5s54uvueL5bjChHwEb1ZGOtST9Zt86cj
YA/xtVHnDXCJbhohpzQI6dK96NegONZVDaxEohVCyYYOgI1I14Bxu0ZCMm5GjwoO
QohnUfEJ+BRgZqFpbsnYCE+PoVayVVFoLA+GMeqbQ2SHej1Pr1K0dbjUz6SAk8/+
DL7h8d+YAtflATsMtdsVJ4WzEfvZbSbiYKYmlVC6zk6ooXWadvQ5+aezVes9WMpH
YnAoScuKoeerRuKlsSU7u+XCmy/i7Hii5FwMrSvIL2GLtVE+tJFCTABA55OWZikt
ULMQfg3P2Hk3GFIE35M10mSjKQkGhz06WC5UQ7f2Xl9GzO6PqRSorzugewgMK6L4
SnN7XBFnUHHqx1bWNkUG8NPYB6Zs7UDHygemTWxqqxun43s501DNTSunCKIhwFbt
1ol5gOvYAFG+BXxnggBT815Mgz1Zht3S9CuprAgz0grNEwAYjRTm1PSaX3t8I1kv
oUUuMF6BzWLHJ66uZKOCsPs3ouGq+G3GfWUCAwEAAaNFMEMwDgYDVR0PAQH/BAQD
AgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFCj8lmcR7loB9zAP/feo
t1eIHWmIMA0GCSqGSIb3DQEBCwUAA4ICAQCu46fF0Tr2tZz1wkYt2Ty3OU77jcG9
zYU/7uxPqPC8OYIzQJrumXKLOkTYJXJ7k+7RQdsn/nbxdH1PbslNDD3Eid/sZsF/
dFdGR1ZYwXVQbpYwEd19CvJTALn9CyAZpMS8J2RJrmdScAeSSb0+nAGTYP7GvPm+
8ktOnrz3w8FtzTw+seuCW/DI/5UpfC9Jf+i/3XgxDozXWNW6YNOIw/CicyaqbBTk
5WFcJ0WJN+8qQurw8n+sOvQcNsuDTO7K3Tqu0wGTDUQKou7kiMX0UISRvd8roNOl
zvvokNQe4VgCGQA+Y2SxvSxVG1BaymYeNw/0Yxm7QiKSUI400V1iKIcpnIvIedJR
j2bGIlslVSV/P6zkRuF1srRVxTxSf1imEfs8J8mMhHB6DkOsP4Y93z5s6JZ0sPiM
eOb0CVKul/e1R0Kq23AdPf5eUv63RhfmokN1OsdarRKMFyHphWMxqGJXsSvRP+dl
3DaKeTDx/91OSWiMc+glHHKKJveMYQLeJ7GXmcxhuoBm6o4Coowgw8NFKMCtAsp0
ktvsQuhB3uFUterw/2ONsOChx7Ybu36Zk47TKBpktfxDQ578TVoZ7xWSAFqCPHvx
A5VSwAg7tdBvORfqQjhiJRnhwr50RaNQABTLS0l5Vsn2mitApPs7iKiIts2ieWsU
EsdgvPZR2e5IkA==
-----END CERTIFICATE-----`
	caKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
	caCRL = `-----BEGIN X509 CRL-----
MIICpjCBjwIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhDZXJ0QXV0aBcN
MjMwMTAzMTAzMzI4WhcNMjUwMTAyMTAzMzI4WjAjMCECEHUfHtKUGlg/86yMN/aM
xxsXDTIzMDEwMzEwMzMyOFqgIzAhMB8GA1UdIwQYMBaAFCj8lmcR7loB9zAP/feo
t1eIHWmIMA0GCSqGSIb3DQEBCwUAA4ICAQAJf6MBMUc3xWKB6fy0VoPbXQjVTsL4
Yjm5lKaCtvcRiJ6onaITfJL6V3OCy/MAe94sHynvK3DyyYvxJ0ms7y+kmEtFzHwz
T+hBPHaEV/Ccamt+3zRZwndwEMomkQz5tBipwimOlsYXWqItjhXHcLLr84jWgqpD
JHcfDmLswCeJVqe8xyYSYCnWMjQ3sn0h+arjm53SdHTULlsjgKeX/ao2IJwt1Ddr
APYKZ/XBWq9vBq3l4l2Ufj16fUBY5NeHTjQcLLrkwmBwpSb0YS8+jBwmOwo1HwEF
MEwADBTHI2jT4ygzzKefVETfcSk4CuIQ1ve0qQL7KY5Fg5AXwbRycev6R0vEHR82
oOPAqg+dYgKtdkxK5QZrNLenloq6x0/3oEThwOg3J17+eCYjixBC+3PoUzLa+yfZ
xSQ/kkcRJExEhadw5I9TI7sEUk1RjDCl6AtHg53LQifokiLLfMRptOiN3a4NlLJ2
HNXfWUltRUnr6MCxk+G7U5Zaj1QtCN3Aldw+3xcJr7FOBU23VqRT22XbfW+B1gsr
4eNlw5Kk/PDF/WZeGbrwy7fvpSoFsDYI8lpVlzKVwLampIZVhnWsfaf7jk/pc4T0
6iZ+rnB6CP4P+LM34jKYiAtz+iufjEB6Ko0jN0ZWCznDGDVgMwnVynGJNKU+4bl8
vC4nIbS2OhclcA==
-----END X509 CRL-----`
	client1Crt = `-----BEGIN CERTIFICATE-----
MIIEIDCCAgigAwIBAgIQWwKNgBzKWM8ewyS4K78uOTANBgkqhkiG9w0BAQsFADAT
MREwDwYDVQQDEwhDZXJ0QXV0aDAeFw0yMzAxMDMxMDIzMTFaFw0zMzAxMDMxMDMw
NDVaMBIxEDAOBgNVBAMTB2NsaWVudDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQC+jwuaG0FSpPtE5mZPBgdacAhXXa51/TIT18HTm+QnOYUcGRel3AuZ
OBWv3fOallW8iQX3i+M78cKeTMWOS5RGXCdDe866pYXEyUkZFRRSA/6573Dz5dJ/
DZOCsgW+91JlSkM1+FYE9cpt4qLkdAjSRXIoebcA64K60wqZr1Js+pQrH3leT9wu
33dM3KHkDHOeMj6X/V1me22htndD/DUlWmPc58jMFbcvxFG3oUBB9U65LJBwJNzr
XWVcli2QirZ0fLkC7Lo2FIYuN1qeU/8A/T4TTInZb/eW3Faqv4RuhjWPXFLqkdIP
4AzDxCNuhlWqyv9nfgegXAHOHpXZMDKxAgMBAAGjcTBvMA4GA1UdDwEB/wQEAwID
uDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFKloKnzI
w7YYnjm1sKU+LgvT5dU0MB8GA1UdIwQYMBaAFCj8lmcR7loB9zAP/feot1eIHWmI
MA0GCSqGSIb3DQEBCwUAA4ICAQAeja0rK7I14ibgis9vSPXAGmmKpagIjvZiYCE6
Ti/Rq6qbyQ6tKL08NxR2XPNjoXfxwGOGgboWR86S7WT93pz3HkftAjTfzUnxnXOx
S7dWfq+g0uY/3ql6IFDQBpGKHu/KN8/1Pvn39FiYSdCaM66bwyFukcvBXace+aC1
M6jzVsscxoCCjXhcZl++Tjpf6TzGMd8OFyArBQmOUCoFrTcMzLPKSAROAHp0k+Ju
HHNgLdgXPQCfAgRbWnqq2o2moApe7+gzMS+1X0eKhIXYS7csK8rFvGzjH/ANDo9A
8+AFcJh8YiIlEVI8nCb3ERdpAbu6G5xkfUDkqcWjCAhuokrbeFmU82RQOc3TQZc9
NMHfTkCOPhaIdPI/kC+fZkdz+5ftDCl/radSljeMX+/y0DVQUOtrQzyT1PBN0vCx
L+FCzj0fHJwdoDiFLxDLLN1pYWsxMnIichpg625CZM9r5i183yPErXxxQPydcDrX
Y6Ps7rGiU7eGILhAfQnS1XUDvH0gNfLUvO5uWm6yO4yUEDWkA/wOTnrc8Z5Waza+
kH+FmxnYpT1rMloTSoyiHIPvTq1nVJ8LILUODZAxW+ZHmccGgOpIN/DWuWunVRHG
tuaTSgU1xjWl2q/SeoS2DpiEKTIAZZQ5CTD819oc8SnLTzK0ISRpBXKg13AF2uJD
G9q7sA==
-----END CERTIFICATE-----`
	client1Key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvo8LmhtBUqT7ROZmTwYHWnAIV12udf0yE9fB05vkJzmFHBkX
pdwLmTgVr93zmpZVvIkF94vjO/HCnkzFjkuURlwnQ3vOuqWFxMlJGRUUUgP+ue9w
8+XSfw2TgrIFvvdSZUpDNfhWBPXKbeKi5HQI0kVyKHm3AOuCutMKma9SbPqUKx95
Xk/cLt93TNyh5AxznjI+l/1dZnttobZ3Q/w1JVpj3OfIzBW3L8RRt6FAQfVOuSyQ
cCTc611lXJYtkIq2dHy5Auy6NhSGLjdanlP/AP0+E0yJ2W/3ltxWqr+EboY1j1xS
6pHSD+AMw8QjboZVqsr/Z34HoFwBzh6V2TAysQIDAQABAoIBAFaIHnycY81jnbZr
6Yl4813eAeuqXs61a0gXcazl3XTyab+YpWRrx9iL3009PKG2Iri6gDspCsbtwbKg
qhUzvOE2d53tWrLm9xelT8xUBiY4KjPEx0X51txbDeELdhCBvqjAUETxwB4Afyvm
/pE/H8JcRrqair+gMn0j2GxxcLyLQt8/DBaqbs50QDxYbLTrfZzXi3R5iAMmtGDM
ZuhBDJYjw/PdJnmWcCkeEFa731ZwHISvDFJtZ6kv0yU7guHzvDWOFlszFksv8HRI
s46i1AqvdLd3M/xVDWi2f5P3IuOK80v2xrTZAbJSc9Fo/oHhO+9mWoxnGF2JE2zO
cabYfAECgYEA/EIw0fvOLabhmsLTItq7p76Gt1kE2Rsn+KsRH+H4vE3iptHy1pks
j/aohQ+YeZM3KtsEz12dtPfUBQoTMfCxpiHVhhpX5JLyc6OAMWhZUItQX2X0lzeY
oPRdbEMRcfxOKjb3mY5T2h9TVUieuspE2wExYFRMaB8BT4pio86iWYUCgYEAwWKV
pP7w1+H6bpBucSh89Iq0inIgvHpFNz0bpAFTZV+VyydMzjfkY8k6IqL5ckr2aDsY
vk6XLClJi6I2qeQx/czIrd+xCWcSJPLTcjtKwv0T01ThNVq+ev1NBUqU03STyaJa
p14r4dIYxpZs13s+Mdkzr7R8uv4J5Y03AP90xj0CgYEA4j0W/ezBAE6QPbWHmNXl
wU7uEZgj8fcaBTqfVCHdbDzKDuVyzqZ3wfHtN9FB5Z9ztdrSWIxUec5e99oOVxbQ
rPfhQbF0rIpiKfY0bZtxpvwbLEQLdmelWo1vED6iccFf9RpxO+XbLGA14+IKgeoQ
kP5j40oXcLaF/WlWiCU1k+UCgYEAgVFcgn5dLfAWmLMKt678iEbs3hvdmkwlVwAN
KMoeK48Uy0pXiRtFJhldP+Y96tkIF8FVFYXWf5iIbtClv0wyxeaYV/VbHM+JCZ48
GYpevy+ff1WmWBh7giE6zQwHo7O0VES2XG+T5qmpGbtjw2DNwWXes2N9eUoB8jhR
jOBHBX0CgYEA6Ha3IdnpYyODII1W26gEPnBoUCk1ascsztAqDwikBgMY9605jxLi
t3L261iTtN4kTd26nPTsNaJlEnKfm7Oqg1P3zpYLmC2JoFVrOyAZVhyfLACBMV9g
Dy1qoA4qz5jjtwPQ0bsOpfE6/oXdIZZdgyi1CmVRMNF0z3KNs1LhLLU=
-----END RSA PRIVATE KEY-----`
	// client 2 crt is revoked
	client2Crt = `-----BEGIN CERTIFICATE-----
MIIEIDCCAgigAwIBAgIQdR8e0pQaWD/zrIw39ozHGzANBgkqhkiG9w0BAQsFADAT
MREwDwYDVQQDEwhDZXJ0QXV0aDAeFw0yMzAxMDMxMDIzMTRaFw0zMzAxMDMxMDMw
NDVaMBIxEDAOBgNVBAMTB2NsaWVudDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQC/UZqUxeP15lhXBmPmpS5SdI470R75fxmN14FhYwTS3FsDoT+evqRg
II4Qo/wqbaGrk/BsbzB7ToVWqpkyZ58hYPdtLjKtBBHYsSCNCoKZEVJTz5JdW3sj
CKRsG3zPVhFjJcYW9pKsr/CGIIDWAfkuuwR+R/NHkUFSjEP5N9qMAc9wBvskxV84
YAJJykPD9rG8PjXHOKsfNUhH+/QfbqMkCeETJ1sp66o3ilql2aZ0m6K6x4gB7tM7
NZnM4eztLZbAnQVQhNBYCR6i7DGI2dujujPbpCqmSqSb42n+3a2o844k6EnU76HJ
RZwhd3ypy9CvTdkya5JbK+aKKo8fGFHbAgMBAAGjcTBvMA4GA1UdDwEB/wQEAwID
uDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFLItEDE1
gVYfe7JSax5YAjEW8tmzMB8GA1UdIwQYMBaAFCj8lmcR7loB9zAP/feot1eIHWmI
MA0GCSqGSIb3DQEBCwUAA4ICAQCZRStHCbwmhmH4tu7V5ammmQhn1TKcspV86cXz
JQ4ZM11RvGpRLTmYuRkl5XloMuvB8yYAE1ihhkYOhgU6zSAj33kUQSx6cHXWau7T
NjTchptKX+b17GR/yuFwIR3TugArBsnwyuUdts478gTY+MSgTOWWyOgWl3FujiEJ
GJ7EgKde4jURXv2qjp6ZtSVqMlAa3y8C3S8nLdyt9Rf8CcSjEy/t8t0JhoMYCvxg
o1k7QhMCfMYjjEIuEyDVOdCs2ExepG1zUVBP5h5239sXvLKrOZvgCZkslyTNd/m9
vv4yR5gLgCdt0Ol1uip0p910PJoSqX6nZNfeCx3+Kgyc7crl8PrsnUAVoPgLxpVm
FWF+KlUbh2KiYTuSi5cH0Ti9NtWT3Qi8d4WhmjFlu0zD3EJEUie0oYfHERiO9bVo
5EAzERSVhgQdxVOLgIc2Hbe1JYFf7idyqASRw6KdVkW6YIC/V/5efrJ1LZ5QNrdv
bmfJ5CznE6o1AH9JsQ8xMi+kmyn/It1uMWIwP/tYyjQ98dlOj2k9CHP2RzrvCCY9
yZNjs2QC5cleNdSpNMb2J2EUYTNAnaH3H8YdbT0scMHDvre1G7p4AjeuRJ9mW7VK
Dcqbw+VdSAPyAFdiCd9x8AU3sr28vYbPbPp+LsHQXIlYdnVR0hh2UKF5lR8iuqVx
y05cAQ==
-----END CERTIFICATE-----`
	client2Key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAv1GalMXj9eZYVwZj5qUuUnSOO9Ee+X8ZjdeBYWME0txbA6E/
nr6kYCCOEKP8Km2hq5PwbG8we06FVqqZMmefIWD3bS4yrQQR2LEgjQqCmRFSU8+S
XVt7IwikbBt8z1YRYyXGFvaSrK/whiCA1gH5LrsEfkfzR5FBUoxD+TfajAHPcAb7
JMVfOGACScpDw/axvD41xzirHzVIR/v0H26jJAnhEydbKeuqN4papdmmdJuiuseI
Ae7TOzWZzOHs7S2WwJ0FUITQWAkeouwxiNnbo7oz26Qqpkqkm+Np/t2tqPOOJOhJ
1O+hyUWcIXd8qcvQr03ZMmuSWyvmiiqPHxhR2wIDAQABAoIBAQCGAtE2uM8PJcRn
YPCFVNr3ovEmcTszJJZvxq632rY8RWHzTvXTalKVivg4K8WsqpJ+LuhP7CqXlM7N
gD5DElZi+RsXfS6+BoXBtYDJir0kHv/9+P3bKwM77QfPOgnY6b7QJlt1Jk5ja/Ic
4ZOdVFCJLTLeieOdE+AfxGSwozEQs9N3wBjPi6i5Rarc6i8HbuSemp/KfXrSR/Sh
EFajk0l3nFVgr3VOLGsV/ieT6EW42p6ZA1ZBEi4sr4hN49zU2Vpj+lXBl/RhVGgM
6cSYJkOP98eD2t9cjHyZFqSw18/UqTNonMfoT2uvSNni9/jAouzkt7SwaPAqQpjE
BfiJnK9RAoGBAMNdK6AhS+9ouQEP5v+9ubQ3AIEMYb+3uVR+1veCBqq49J0Z3tgk
7Ts5eflsYnddmtys+8CMnAvh+1EedK+X/MQyalQAUHke+llt94N+tHpSPDw/ZHOy
koyLFg6efQr+626x6o33jqu+/9fu7Szxv41tmnCfh9hxGXda3aiWHsUdAoGBAPqz
BQVWI7NOJmsiSB0OoDs+x3fqjp31IxEw63t+lDtSTTzxCU53sfie9vPsKdPFqR+d
yNa5i5M8YDuaEjbN3hpuOpRWbfg2aPVyx3TNPp8bHNNUuJkCQ4Z2b0Imlv4Sycl+
CCMMXvysIAomxkAZ3Q3BsSAZd2n+qvLvMt2jGZlXAoGAa/AhN1LOMpMojBauKSQ4
4wH0jFg79YHbqnx95rf3WQHhXJ87iS41yCAEbTNd39dexYfpfEPzv3j2sqXiEFYn
+HpmVszpqVHdPeXM9+DcdCzVTPA1XtsNrwr1f9Q/AAFCMKGqFw/syqU3k6VVcxyK
GeixiIILuyEZ0eDpUMjIbV0CgYBbwvLvhRwEIXLGfAHRQO09QjlYly4kevme7T0E
Msym+fTzfXZelkk6K1VQ6vxUW2EQBXzhu4BvIAZJSpeoH6pQGlCuwwP1elTool6H
TijBq/bdE4GN39o/eVI38FAMJ2xcqBjqWzjZW1dO3+poxA65XlAq46dl0KVZzlvb
7DsOeQKBgQCW8iELrECLQ9xhPbzqdNEOcI4wxEI8oDNLvUar/VnMrSUBxi/jo3j2
08IOKMKqSl+BX77ftgazhyL+hEgxlZuPKeqUuOWcNxuAs0vK6Gc5+Y9UpQEq78nH
uaPG3o9EBDf5eFKi76o+pVtqxrwhY88M/Yw0ykEA6Nf7RCo2ucdemg==
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
func (fs *MockOsFs) Open(name string, offset int64) (vfs.File, *pipeat.PipeReaderAt, func(), error) {
	if fs.reader != nil {
		return nil, fs.reader, nil, nil
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
func (fs *MockOsFs) Remove(name string, isDir bool) error {
	if fs.err != nil {
		return fs.err
	}
	return os.Remove(name)
}

// Rename renames (moves) source to target
func (fs *MockOsFs) Rename(source, target string) error {
	return os.Rename(source, target)
}

// GetMimeType returns the content type
func (fs *MockOsFs) GetMimeType(name string) (string, error) {
	if fs.err != nil {
		return "", fs.err
	}
	return "application/custom-mime", nil
}

func newMockOsFs(atomicUpload bool, connectionID, rootDir string, reader *pipeat.PipeReaderAt, err error) vfs.Fs {
	return &MockOsFs{
		Fs:                      vfs.NewOsFs(connectionID, rootDir, ""),
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
		assert.EqualError(t, err, fmt.Sprintf("cannot login user with invalid home dir: %#v", u.HomeDir))
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
	fs := vfs.NewOsFs("connID", user.HomeDir, "")
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
	fs := vfs.NewOsFs("connID", user.HomeDir, "")
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
	assert.Error(t, err)
	err = davFile.Close()
	assert.NoError(t, err)

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile+".unknown1",
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
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

	baseTransfer = common.NewBaseTransfer(nil, connection.BaseConnection, nil, testFilePath, testFilePath, testFile,
		common.TransferDownload, 0, 0, 0, 0, false, fs, dataprovider.TransferQuota{})
	davFile = newWebDavFile(baseTransfer, nil, nil)
	davFile.Fs = vfs.NewOsFs("id", user.HomeDir, "")
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
		davFile.Fs = vfs.NewOsFs("id", user.HomeDir, "")
		fi, err = davFile.Stat()
		if assert.NoError(t, err) {
			ctype, err := fi.(*webDavFileInfo).ContentType(ctx)
			assert.NoError(t, err)
			assert.Equal(t, "text/plain; charset=utf-8", ctype)
		}
		err = davFile.Close()
		assert.NoError(t, err)
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

	fs = vfs.NewOsFs(fs.ConnectionID(), user.GetHomeDir(), "")
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
	err = dataprovider.UpdateFolder(&folder, folder.Users, folder.Groups, "", "")
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
	err = dataprovider.UpdateFolder(&folder, folder.Users, folder.Groups, "", "")
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
