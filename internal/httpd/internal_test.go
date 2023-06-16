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

package httpd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
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
MIIJJwIBAAKCAgEAxq6Wl1IhhgvGdM8M2IVI7dwnv3yShJygZsnREQSEW0xeWJL5
DtNeHCME5WByFUAlZKpePtW8TNwln9DYDtgNSMiWwvO/wR0mXsyU8Ma4ZBMlX0oO
kWo1Ff/M/u8YY9X78Vvwdt62Yt7QmU5oUUW2HdAgh4AlhKJSjm3t0uDP5s54uvue
L5bjChHwEb1ZGOtST9Zt86cjYA/xtVHnDXCJbhohpzQI6dK96NegONZVDaxEohVC
yYYOgI1I14Bxu0ZCMm5GjwoOQohnUfEJ+BRgZqFpbsnYCE+PoVayVVFoLA+GMeqb
Q2SHej1Pr1K0dbjUz6SAk8/+DL7h8d+YAtflATsMtdsVJ4WzEfvZbSbiYKYmlVC6
zk6ooXWadvQ5+aezVes9WMpHYnAoScuKoeerRuKlsSU7u+XCmy/i7Hii5FwMrSvI
L2GLtVE+tJFCTABA55OWZiktULMQfg3P2Hk3GFIE35M10mSjKQkGhz06WC5UQ7f2
Xl9GzO6PqRSorzugewgMK6L4SnN7XBFnUHHqx1bWNkUG8NPYB6Zs7UDHygemTWxq
qxun43s501DNTSunCKIhwFbt1ol5gOvYAFG+BXxnggBT815Mgz1Zht3S9CuprAgz
0grNEwAYjRTm1PSaX3t8I1kvoUUuMF6BzWLHJ66uZKOCsPs3ouGq+G3GfWUCAwEA
AQKCAgB1dNFiNBPNgziX5a/acTFkLTryYVrdOxs4qScHwHve3Y8JHhpPQXXpfGpw
kEvhdEKm+HEvBHyFk8BKctTIMcHovW0jY6aBLBJ7CMckcNahkxAM/WMPZJJtpwQx
0nfAzchcL9ZA7/kzCjaX61qQcX3wshIJCSElADF+Mk7e1DkUYgvNvuMNj045rdEX
K7F4oeXPfR0TZkPrjoF+iCToNReKF7i9eG2sjgHnnVIDR/KQWr9YculA6he4t83Q
WQbjh+2qkrbz6SX0/17VeoJCPwmeot4JuRoWD7MB1pcnCTFkmujiqaeQd+X/xi9N
nr9AuTxWZRH+UIAIWPCKZX0gcTHYNJ7Qj/bwIOx6xIISrH4unvKtJOI71NBBognY
wBlDbz5gST1GKdZHsvqsi2sfFF7HAxiUzLHTofsYr0joNgHTJcXlJrtDrjbEt9mm
8f1tVc+ooQYb3u2BJlrIn3anUytVXEjYRje1bBYRaE1uuVG5QdHInc6V7rV3LfvX
IByObtklvCLgCxZm6QUGedb16KV+Prt1W0Yvk6kMOldhG2uBRrt2vC8QxgNzRs90
LIwBhv1hg++EU9RIaXN6we9ZiPs164VD1h6f8UeShAFtQN9eByqRaYmJzDDNh8Py
CK/mR4mlyjdAArm42HpsPM0DeCpgjCQnsQFCihXe9++OT8enAQKCAQEAzbFWCmL0
JsvsQopeO9H7NrQIZRql1bfPOcjvDBtYZgjR91q84zEcUUmEjVMtD/oPSk4HdjEK
ljmGAjOvIFpdgk0YAtA4+kP+zvEoaKLfKGLNXdeNdYPJBvHMcbLrOknFJZ7PVoJA
5hQHMazX+JzaeCB2PTcGWUSnu4Lw4eTho/dmdlwsGS7HjTPw7LZnQfrJ57NHVX6n
ZtwfjgxBmyE+rImpPPytuKGAgbH9qhrUqCNh6MQ6ZcqN4aHAI8j72IW8rwSPkYZ3
mRpLtrvKKKcAp3YWh75WAtG0aqVQ876wpcM7Nxa+0TM9UzbF+xtoyz1/BCp3hrCA
0g6D40YRiPf+OQKCAQEA90ZNRP2vEEUbkXkxZGyrOq9P7FEgwt1Tg3kvCVrralst
Db/v2ZQR8IyhJwNtBczXKpuxrv978zKjrDhqBMBaL8wXUrmf98has14ZvvrgiCzE
oBuVRbRrJ8ksY2YyzBkW3OjO9iI7knbVT50xasbqhtHj5Q3DWMOt0bcAAjcZlRK3
gD1e25/YOBR3C1XVylGGDH0jU/7VHzkedy8rwr7vPwMS7crU6l74mxre7ZS5Mb9T
nqoP/VgrHzoz+uVXTXk0FvJBENrDm340RxsBrK7/ePA8ngp5ZzfUZ47eYOSYBZPD
WYG1+Z99/ZLzZ/AJvp2HiGPDG5lXJjKg/Y7iWis4jQKCAQBaE7r2OXdqNgt06Ft0
HvTAc/7pJ85P1Xrud0wYJTGFHX+1rwrhA3S/NE7UBQTK5lsj0x/5ZmiYeQBynmem
52vj0BcfxEfvcS95OKrVh93qNbpxyh+swtWaMPGzKQNSN1QasX1jCQ+aslKkMmkx
+p7B1JVzIVGqbiJ2P1V112HpCELaumqlbJL/BywOvaJiho085onqqthsdyFqd3uT
j+9+Z5qxloYNQMyh/2xyveU67KPH54cbZKTVlpwqD64amBaVHo4w0I43ggh+MabK
PrhOnawoLfZErckwmszksTFyphice119B89nTalN2ib+OiQRkvddCJahZrHjKaAs
N04hAoIBACwKAUkARWWIaViHVRylnfldr8ZOzJ7n/C+2LYJlBvhyNJv2SyldDbTh
1vGz0n7t9IRKJmMcbV7q7euGQJuIBofsuVqqZKskq8K2R6+Tztlx37MENpmrgEod
siIh2XowHbpKXFHJ1wJG18bOIDb8JljMmOH6iYgNka+AAChk19GM+9GDHJnQ5hlW
y7zhFKpryov+3YPgJuTgr2RaqliM2N9IFN70+Oak83HsXzfA/Rq3EJV5hE+CnGt7
WjadEediZryPeLcfvya6W2UukiXHJQjNAH7FLsoLT3ECKOjozYpwvqH6UAadOTso
KOGiBppERBcubVlE/hh3e+SsxfN5LyECggEATftYF8rp47q8LKCJ/QHk1U+MZoeU
hkMuov2/Du4Cj3NsAq/GmdU2nuPGHUoHZ90rpfbOdsg4+lYx3aHSfVwk46xy6eE3
LsC30W9NUEc14pveuEfkXWwIhmkwmA8n53wpjWf1nnosXa6UCHj6ycoRuwkH1QN1
muQumpvL1gR8BV4H0vnhd0bCFHH4wyPKy0yTaXXsUE5NBCRbyOqehSLMOjCSgKUK
5oDwxh7pnJf1cchKpG0ODJR60vukdjcfqU9UN/SMvpYLnBiozM3QrxwHKROsnZzm
Q0gSWphVd9QaWWD3wtHYPV3RkE5F4H+mKjVcnkES3aQnow7b/FSnhdJ4dw==
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
	defaultAdminUsername = "admin"
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
				LogoPath:       "path1",
				LoginImagePath: "login1.png",
				DefaultCSS:     "my.css",
			},
			WebClient: UIBranding{
				FaviconPath:    "favicon1.ico",
				DisclaimerPath: "../path2",
				ExtraCSS:       []string{"1.css"},
			},
		},
	}
	b.checkBranding()
	assert.Equal(t, "/favicon.ico", b.Branding.WebAdmin.FaviconPath)
	assert.Equal(t, "/path1", b.Branding.WebAdmin.LogoPath)
	assert.Equal(t, "/login1.png", b.Branding.WebAdmin.LoginImagePath)
	assert.Equal(t, "/my.css", b.Branding.WebAdmin.DefaultCSS)
	assert.Len(t, b.Branding.WebAdmin.ExtraCSS, 0)
	assert.Equal(t, "/favicon1.ico", b.Branding.WebClient.FaviconPath)
	assert.Equal(t, "/path2", b.Branding.WebClient.DisclaimerPath)
	assert.Equal(t, "/img/login_image.png", b.Branding.WebClient.LoginImagePath)
	if assert.Len(t, b.Branding.WebClient.ExtraCSS, 1) {
		assert.Equal(t, "/1.css", b.Branding.WebClient.ExtraCSS[0])
	}
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
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebAddUserPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebUpdateUserPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebTemplateFolderPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebTemplateUserPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

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
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebUpdateFolderPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebGetConnections(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebConfigsPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

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
	getMetadataChecks(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	startMetadataCheck(rr, req)
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
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebUpdateUserGet(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebUpdateRolePost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebAddRolePost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebAddAdminPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebAddGroupPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebUpdateGroupPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebAddEventActionPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebUpdateEventActionPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebAddEventRulePost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebUpdateEventRulePost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	server.handleWebUpdateIPListEntryPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

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
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	form := make(url.Values)
	req, _ = http.NewRequest(http.MethodPost, webIPListPath+"/1", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("type", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr = httptest.NewRecorder()
	server.handleWebAddIPListEntryPost(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid token claims")
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

	form := make(url.Values)
	form.Set(csrfFormToken, createCSRFToken(""))
	form.Set("status", "1")
	form.Set("default_users_expiration", "30")
	req, _ := http.NewRequest(http.MethodPost, path.Join(webAdminPath, "admin"), bytes.NewBuffer([]byte(form.Encode())))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("username", "admin")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleWebUpdateAdminPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")
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
	assert.Contains(t, rr.Body.String(), "token is unauthorized")

	ip := "127.1.1.4"
	tokenString := createOAuth2Token(xid.New().String(), ip)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, webOAuth2RedirectPath+"?state="+tokenString, nil)
	assert.NoError(t, err)
	req.RemoteAddr = ip
	server.handleOAuth2TokenRedirect(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "no auth request found for the specified state")
}

func TestOAuth2Token(t *testing.T) {
	// invalid token
	_, err := verifyOAuth2Token("token", "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to verify OAuth2 state")
	}
	// bad audience
	claims := make(map[string]any)
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(tokenDuration)
	claims[jwt.AudienceKey] = []string{tokenAudienceAPI}

	_, tokenString, err := csrfTokenAuth.Encode(claims)
	assert.NoError(t, err)
	_, err = verifyOAuth2Token(tokenString, "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid OAuth2 state")
	}
	// bad IP
	tokenString = createOAuth2Token("state", "127.1.1.1")
	_, err = verifyOAuth2Token(tokenString, "127.1.1.2")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid OAuth2 state")
	}
	// ok
	state := xid.New().String()
	tokenString = createOAuth2Token(state, "127.1.1.3")
	s, err := verifyOAuth2Token(tokenString, "127.1.1.3")
	assert.NoError(t, err)
	assert.Equal(t, state, s)
	// no jti
	claims = make(map[string]any)

	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(tokenDuration)
	claims[jwt.AudienceKey] = []string{tokenAudienceOAuth2, "127.1.1.4"}
	_, tokenString, err = csrfTokenAuth.Encode(claims)
	assert.NoError(t, err)
	_, err = verifyOAuth2Token(tokenString, "127.1.1.4")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid OAuth2 state")
	}
	// encode error
	csrfTokenAuth = jwtauth.New("HT256", util.GenerateRandomBytes(32), nil)
	tokenString = createOAuth2Token(xid.New().String(), "")
	assert.Empty(t, tokenString)

	server := httpdServer{}
	server.initializeRouter()
	rr := httptest.NewRecorder()
	testReq := make(map[string]any)
	testReq["base_redirect_url"] = "http://localhost:8082"
	asJSON, err := json.Marshal(testReq)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, webOAuth2TokenPath, bytes.NewBuffer(asJSON))
	assert.NoError(t, err)
	handleSMTPOAuth2TokenRequestPost(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "unable to create state token")

	csrfTokenAuth = jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil)
}

func TestCSRFToken(t *testing.T) {
	// invalid token
	err := verifyCSRFToken("token", "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to verify form token")
	}
	// bad audience
	claims := make(map[string]any)
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(tokenDuration)
	claims[jwt.AudienceKey] = []string{tokenAudienceAPI}

	_, tokenString, err := csrfTokenAuth.Encode(claims)
	assert.NoError(t, err)
	err = verifyCSRFToken(tokenString, "")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "form token is not valid")
	}

	// bad IP
	tokenString = createCSRFToken("127.1.1.1")
	err = verifyCSRFToken(tokenString, "127.1.1.2")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "form token is not valid")
	}

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(tokenDuration)
	claims[jwt.AudienceKey] = []string{tokenAudienceAPI}
	_, tokenString, err = csrfTokenAuth.Encode(claims)
	assert.NoError(t, err)

	r := GetHTTPRouter(Binding{
		Address:         "",
		Port:            8080,
		EnableWebAdmin:  true,
		EnableWebClient: true,
		EnableRESTAPI:   true,
		RenderOpenAPI:   true,
	})
	fn := verifyCSRFHeader(r)
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, path.Join(userPath, "username"), nil)
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
	tokenString = createCSRFToken("172.16.1.2")
	req.Header.Set(csrfHeaderToken, tokenString)
	rr = httptest.NewRecorder()
	fn.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "the token is not valid")

	csrfTokenAuth = jwtauth.New("PS256", util.GenerateRandomBytes(32), nil)
	tokenString = createCSRFToken("")
	assert.Empty(t, tokenString)

	csrfTokenAuth = jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil)
}

func TestCreateShareCookieError(t *testing.T) {
	username := "share_user"
	pwd := "pwd"
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
		tokenAuth: jwtauth.New("TS256", util.GenerateRandomBytes(32), nil),
	}
	form := make(url.Values)
	form.Set("share_password", pwd)
	form.Set(csrfFormToken, createCSRFToken("127.0.0.1"))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", share.ShareID)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, path.Join(webClientPubSharesPath, share.ShareID, "login"),
		bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = "127.0.0.1:2345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	server.handleClientShareLoginPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), common.ErrInternalFailure.Error())

	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)
}

func TestCreateTokenError(t *testing.T) {
	server := httpdServer{
		tokenAuth: jwtauth.New("PS256", util.GenerateRandomBytes(32), nil),
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
			Password: "pwd",
		},
	}
	req, _ = http.NewRequest(http.MethodGet, userTokenPath, nil)

	server.generateAndSendUserToken(rr, req, "", user)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	rr = httptest.NewRecorder()
	form := make(url.Values)
	form.Set("username", admin.Username)
	form.Set("password", admin.Password)
	form.Set(csrfFormToken, createCSRFToken("127.0.0.1"))
	req, _ = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	req, _ = http.NewRequest(http.MethodGet, webAdminLoginPath+"?a=a%C3%A2%G3", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err := getAdminFromPostFields(req)
	assert.Error(t, err)

	req, _ = http.NewRequest(http.MethodPost, webAdminEventActionPath+"?a=a%C3%AO%GG", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = getEventActionFromPostFields(req)
	assert.Error(t, err)

	req, _ = http.NewRequest(http.MethodPost, webAdminEventRulePath+"?a=a%C3%AO%GG", nil)
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
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

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
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	req, _ = http.NewRequest(http.MethodPost, webAdminTwoFactorRecoveryPath+"?a=a%C3%AO%GD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAdminTwoFactorRecoveryPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	req, _ = http.NewRequest(http.MethodPost, webClientTwoFactorPath+"?a=a%C3%AO%GC", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientTwoFactorPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	req, _ = http.NewRequest(http.MethodPost, webClientTwoFactorRecoveryPath+"?a=a%C3%AO%GD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientTwoFactorRecoveryPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	req, _ = http.NewRequest(http.MethodPost, webAdminForgotPwdPath+"?a=a%C3%A1%GD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAdminForgotPwdPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	req, _ = http.NewRequest(http.MethodPost, webClientForgotPwdPath+"?a=a%C2%A1%GD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientForgotPwdPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	req, _ = http.NewRequest(http.MethodPost, webAdminResetPwdPath+"?a=a%C3%AO%JD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAdminPasswordResetPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	req, _ = http.NewRequest(http.MethodPost, webAdminRolePath+"?a=a%C3%AO%JE", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebAddRolePost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

	req, _ = http.NewRequest(http.MethodPost, webClientResetPwdPath+"?a=a%C3%AO%JD", bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	server.handleWebClientPasswordResetPost(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "invalid URL escape")

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

	rr = httptest.NewRecorder()
	form = make(url.Values)
	form.Set("username", user.Username)
	form.Set("password", "clientpwd")
	form.Set(csrfFormToken, createCSRFToken("127.0.0.1"))
	req, _ = http.NewRequest(http.MethodPost, webClientLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	req.RemoteAddr = "127.0.0.1:4567"
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
	permFn := server.checkPerm(dataprovider.PermAdminAny)
	fn = permFn(r)
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, userPath, nil)
	ctx = jwtauth.NewContext(req.Context(), token, errTest)
	fn.ServeHTTP(rr, req.WithContext(ctx))
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	permFn = server.checkPerm(dataprovider.PermAdminAny)
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
	claims = make(map[string]any)
	claims[claimUsernameKey] = admin.Username
	claims[claimPermissionsKey] = admin.Permissions
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
	claims = make(map[string]any)
	claims[claimUsernameKey] = user.Username
	claims[claimPermissionsKey] = user.Filters.WebClient
	claims[jwt.SubjectKey] = user.GetSignature()
	claims[jwt.ExpirationKey] = time.Now().Add(1 * time.Minute)
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
	user := dataprovider.User{
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

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))

	invalidatedJWTTokens.Store(token, time.Now().Add(-tokenDuration).UTC())
	require.True(t, isTokenInvalidated(req))
	startCleanupTicker(100 * time.Millisecond)
	assert.Eventually(t, func() bool { return !isTokenInvalidated(req) }, 1*time.Second, 200*time.Millisecond)
	stopCleanupTicker()
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
	assert.Contains(t, rr.Body.String(), "login from IP 127.0.0.1 not allowed")

	req.RemoteAddr = testIP
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	req.RemoteAddr = "10.8.0.2"
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	form := make(url.Values)
	form.Set("username", username)
	form.Set("password", password)
	form.Set(csrfFormToken, createCSRFToken(testIP))
	req, err = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = testIP
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "login from IP 10.29.1.9 not allowed")

	form.Set(csrfFormToken, createCSRFToken(validForwardedFor))
	req, err = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = testIP
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", validForwardedFor)
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	cookie := rr.Header().Get("Set-Cookie")
	assert.NotContains(t, cookie, "Secure")

	req, err = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = testIP
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", validForwardedFor)
	req.Header.Set(xForwardedProto, "https")
	rr = httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	cookie = rr.Header().Get("Set-Cookie")
	assert.Contains(t, cookie, "Secure")

	req, err = http.NewRequest(http.MethodPost, webAdminLoginPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	req.RemoteAddr = testIP
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
	server.router.Get(recoveryPath, func(w http.ResponseWriter, r *http.Request) {
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
	server.router.Get(recoveryPath, func(w http.ResponseWriter, r *http.Request) {
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

	err = addZipEntry(wr, connection, "/"+filepath.Base(testDir), "/")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "write error")
	}

	err = addZipEntry(wr, connection, "/"+filepath.Base(testDir), path.Join("/", filepath.Base(testDir), "dir"))
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is outside base dir")
	}

	testFilePath := filepath.Join(testDir, "ziptest.zip")
	err = os.WriteFile(testFilePath, util.GenerateRandomBytes(65535), os.ModePerm)
	assert.NoError(t, err)
	err = addZipEntry(wr, connection, path.Join("/", filepath.Base(testDir), filepath.Base(testFilePath)),
		"/"+filepath.Base(testDir))
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "write error")
	}

	connection.User.Permissions["/"] = []string{dataprovider.PermListItems}
	err = addZipEntry(wr, connection, path.Join("/", filepath.Base(testDir), filepath.Base(testFilePath)),
		"/"+filepath.Base(testDir))
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
	err = addZipEntry(wr, connection, user.VirtualFolders[0].VirtualPath, "/")
	assert.Error(t, err)

	user.Filters.FilePatterns = append(user.Filters.FilePatterns, sdk.PatternsFilter{
		Path:           "/",
		DeniedPatterns: []string{"*.zip"},
	})
	err = addZipEntry(wr, connection, "/"+filepath.Base(testDir), "/")
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
		request:        nil,
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
		assert.Contains(t, err.Error(), "invalid token claims")
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
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientDirsPath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientGetDirContents(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid token claims")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientDownloadZipPath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleWebClientDownloadZip(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientEditFilePath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientEditFile(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientSharePath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientAddShareGet(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientSharePath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientUpdateShareGet(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, webClientSharePath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientAddSharePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, webClientSharePath+"/id", nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientUpdateSharePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientSharesPath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientGetShares(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, webClientViewPDFPath, nil)
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleClientGetPDF(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid token claims")
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
	form := make(url.Values)
	form.Set(csrfFormToken, createCSRFToken(""))
	form.Set("public_keys", "")
	req, _ := http.NewRequest(http.MethodPost, webClientProfilePath, bytes.NewBuffer([]byte(form.Encode())))
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
	form = make(url.Values)
	form.Set(csrfFormToken, createCSRFToken(""))
	form.Set("allow_api_key_auth", "")
	req, _ = http.NewRequest(http.MethodPost, webAdminProfilePath, bytes.NewBuffer([]byte(form.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", fmt.Sprintf("jwt=%v", token["access_token"]))
	server.handleWebAdminProfilePost(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
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

func TestMetadataAPI(t *testing.T) {
	username := "metadatauser"
	assert.False(t, common.ActiveMetadataChecks.Remove(username))

	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Password: "metadata_pwd",
			HomeDir:  filepath.Join(os.TempDir(), username),
			Status:   1,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	err := dataprovider.AddUser(&user, "", "", "")
	assert.NoError(t, err)

	assert.True(t, common.ActiveMetadataChecks.Add(username, ""))

	tokenAuth := jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil)
	claims := make(map[string]any)
	claims["username"] = defaultAdminUsername
	claims[jwt.ExpirationKey] = time.Now().UTC().Add(1 * time.Hour)
	token, _, err := tokenAuth.Encode(claims)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, path.Join(metadataBasePath, username, "check"), nil)
	assert.NoError(t, err)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("username", username)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), jwtauth.TokenCtxKey, token))

	rr := httptest.NewRecorder()
	startMetadataCheck(rr, req)
	assert.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())

	assert.True(t, common.ActiveMetadataChecks.Remove(username))
	assert.Len(t, common.ActiveMetadataChecks.Get(""), 0)
	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)

	user.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	err = doMetadataCheck(user)
	assert.Error(t, err)
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
	name, err := getBrowsableSharedPath(share, req)
	assert.NoError(t, err)
	assert.Equal(t, "/", name)
	req, err = http.NewRequest(http.MethodGet, "/share?path=abc", nil)
	require.NoError(t, err)
	name, err = getBrowsableSharedPath(share, req)
	assert.NoError(t, err)
	assert.Equal(t, "/abc", name)

	share.Paths = []string{"/a/b/c"}
	req, err = http.NewRequest(http.MethodGet, "/share?path=abc", nil)
	require.NoError(t, err)
	name, err = getBrowsableSharedPath(share, req)
	assert.NoError(t, err)
	assert.Equal(t, "/a/b/c/abc", name)
	req, err = http.NewRequest(http.MethodGet, "/share?path=%2Fabc/d", nil)
	require.NoError(t, err)
	name, err = getBrowsableSharedPath(share, req)
	assert.NoError(t, err)
	assert.Equal(t, "/a/b/c/abc/d", name)

	req, err = http.NewRequest(http.MethodGet, "/share?path=%2Fabc%2F..%2F..", nil)
	require.NoError(t, err)
	_, err = getBrowsableSharedPath(share, req)
	assert.Error(t, err)

	req, err = http.NewRequest(http.MethodGet, "/share?path=%2Fabc%2F..", nil)
	require.NoError(t, err)
	name, err = getBrowsableSharedPath(share, req)
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
				STSSeconds:           31536000,
				STSIncludeSubdomains: true,
				STSPreload:           true,
				ContentTypeNosniff:   true,
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

	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, webAdminSetupPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)

	for _, webURL := range []string{"/", webBasePath, webBaseAdminPath, webAdminLoginPath, webClientLoginPath} {
		rr = httptest.NewRecorder()
		r, err = http.NewRequest(http.MethodGet, webURL, nil)
		assert.NoError(t, err)
		server.router.ServeHTTP(rr, r)
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, webAdminSetupPath, rr.Header().Get("Location"))
	}

	form := make(url.Values)
	csrfToken := createCSRFToken("")
	form.Set("_form_token", csrfToken)
	form.Set("install_code", installationCode+"5")
	form.Set("username", defaultAdminUsername)
	form.Set("password", "password")
	form.Set("confirm_password", "password")
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Installation code mismatch")

	_, err = dataprovider.AdminExists(defaultAdminUsername)
	assert.Error(t, err)
	form.Set("install_code", installationCode)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)

	_, err = dataprovider.AdminExists(defaultAdminUsername)
	assert.NoError(t, err)

	// delete the admin and test the installation code resolver
	err = dataprovider.DeleteAdmin(defaultAdminUsername, "", "", "")
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	SetInstallationCodeResolver(func(defaultInstallationCode string) string {
		return "5678"
	})

	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webAdminSetupPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)

	for _, webURL := range []string{"/", webBasePath, webBaseAdminPath, webAdminLoginPath, webClientLoginPath} {
		rr = httptest.NewRecorder()
		r, err = http.NewRequest(http.MethodGet, webURL, nil)
		assert.NoError(t, err)
		server.router.ServeHTTP(rr, r)
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, webAdminSetupPath, rr.Header().Get("Location"))
	}

	form = make(url.Values)
	csrfToken = createCSRFToken("")
	form.Set("_form_token", csrfToken)
	form.Set("install_code", installationCode)
	form.Set("username", defaultAdminUsername)
	form.Set("password", "password")
	form.Set("confirm_password", "password")
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Installation code mismatch")

	_, err = dataprovider.AdminExists(defaultAdminUsername)
	assert.Error(t, err)
	form.Set("install_code", "5678")
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminSetupPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)

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
	assert.ErrorIs(t, err, sql.ErrNoRows)
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
	assert.ErrorIs(t, err, sql.ErrNoRows)

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
	}
	c := jwtTokenClaims{}
	c.Decode(token)
	assert.Equal(t, defaultAdminUsername, c.Username)
	assert.Equal(t, nodeID, c.NodeID)
	assert.False(t, c.MustChangePassword)
	assert.True(t, c.MustSetTwoFactorAuth)

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

func TestGetLogEventString(t *testing.T) {
	assert.Equal(t, "Login failed", getLogEventString(notifier.LogEventTypeLoginFailed))
	assert.Equal(t, "Login with non-existent user", getLogEventString(notifier.LogEventTypeLoginNoUser))
	assert.Equal(t, "No login tried", getLogEventString(notifier.LogEventTypeNoLoginTried))
	assert.Equal(t, "Algorithm negotiation failed", getLogEventString(notifier.LogEventTypeNotNegotiated))
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
