// Copyright (C) 2019-2023 Nicola Murino
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
