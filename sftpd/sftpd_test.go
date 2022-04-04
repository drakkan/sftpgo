package sftpd_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/pkg/sftp"
	"github.com/rs/zerolog"
	"github.com/sftpgo/sdk"
	sdkkms "github.com/sftpgo/sdk/kms"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/config"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpdtest"
	"github.com/drakkan/sftpgo/v2/kms"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/mfa"
	"github.com/drakkan/sftpgo/v2/sftpd"
	"github.com/drakkan/sftpgo/v2/util"
	"github.com/drakkan/sftpgo/v2/vfs"
)

const (
	logSender           = "sftpdTesting"
	sftpServerAddr      = "127.0.0.1:2022"
	sftpSrvAddr2222     = "127.0.0.1:2222"
	defaultUsername     = "test_user_sftp"
	defaultPassword     = "test_password"
	defaultSFTPUsername = "test_sftpfs_user"
	testPubKey          = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0= nicola@p1"
	testPubKey1         = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCd60+/j+y8f0tLftihWV1YN9RSahMI9btQMDIMqts/jeNbD8jgoogM3nhF7KxfcaMKURuD47KC4Ey6iAJUJ0sWkSNNxOcIYuvA+5MlspfZDsa8Ag76Fe1vyz72WeHMHMeh/hwFo2TeIeIXg480T1VI6mzfDrVp2GzUx0SS0dMsQBjftXkuVR8YOiOwMCAH2a//M1OrvV7d/NBk6kBN0WnuIBb2jKm15PAA7+jQQG7tzwk2HedNH3jeL5GH31xkSRwlBczRK0xsCQXehAlx6cT/e/s44iJcJTHfpPKoSk6UAhPJYe7Z1QnuoawY9P9jQaxpyeImBZxxUEowhjpj2avBxKdRGBVK8R7EL8tSOeLbhdyWe5Mwc1+foEbq9Zz5j5Kd+hn3Wm1UnsGCrXUUUoZp1jnlNl0NakCto+5KmqnT9cHxaY+ix2RLUWAZyVFlRq71OYux1UHJnEJPiEI1/tr4jFBSL46qhQZv/TfpkfVW8FLz0lErfqu0gQEZnNHr3Fc= nicola@p1"
	testPrivateKey      = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAtN449A/nY5O6cSH/9Doa8a3ISU0WZJaHydTaCLuO+dkqtNpnV5mq
zFbKidXAI1eSwVctw9ReVOl1uK6aZF3lbXdOD8W9PXobR9KUUT2qBx5QC4ibfAqDKWymDA
PG9ylzz64hsYBqJr7VNk9kTFEUsDmWzLabLoH42Elnp8mF/lTkWIcpVp0ly/etS08gttXo
XenekJ1vRuxOYWDCEzGPU7kGc920TmM14k7IDdPoOh5+3sRUKedKeOUrVDH1f0n7QjHQsZ
cbshp8tgqzf734zu8cTqNrr+6taptdEOOij1iUL/qYGfzny/hA48tO5+UFUih5W8ftp0+E
NBIDkkGgk2MJ92I7QAXyMVsIABXco+mJT7pQi9tqlODGIQ3AOj0gcA3X/Ib8QX77Ih3TPi
XEh77/P1XiYZOgpp2cRmNH8QbqaL9u898hDvJwIPJPuj2lIltTElH7hjBf5LQfCzrLV7BD
10rM7sl4jr+A2q8jl1Ikp+25kainBBZSbrDummT9AAAFgDU/VLk1P1S5AAAAB3NzaC1yc2
EAAAGBALTeOPQP52OTunEh//Q6GvGtyElNFmSWh8nU2gi7jvnZKrTaZ1eZqsxWyonVwCNX
ksFXLcPUXlTpdbiummRd5W13Tg/FvT16G0fSlFE9qgceUAuIm3wKgylspgwDxvcpc8+uIb
GAaia+1TZPZExRFLA5lsy2my6B+NhJZ6fJhf5U5FiHKVadJcv3rUtPILbV6F3p3pCdb0bs
TmFgwhMxj1O5BnPdtE5jNeJOyA3T6Doeft7EVCnnSnjlK1Qx9X9J+0Ix0LGXG7IafLYKs3
+9+M7vHE6ja6/urWqbXRDjoo9YlC/6mBn858v4QOPLTuflBVIoeVvH7adPhDQSA5JBoJNj
CfdiO0AF8jFbCAAV3KPpiU+6UIvbapTgxiENwDo9IHAN1/yG/EF++yId0z4lxIe+/z9V4m
GToKadnEZjR/EG6mi/bvPfIQ7ycCDyT7o9pSJbUxJR+4YwX+S0Hws6y1ewQ9dKzO7JeI6/
gNqvI5dSJKftuZGopwQWUm6w7ppk/QAAAAMBAAEAAAGAHKnC+Nq0XtGAkIFE4N18e6SAwy
0WSWaZqmCzFQM0S2AhJnweOIG/0ZZHjsRzKKauOTmppQk40dgVsejpytIek9R+aH172gxJ
2n4Cx0UwduRU5x8FFQlNc/kl722B0JWfJuB/snOZXv6LJ4o5aObIkozt2w9tVFeAqjYn2S
1UsNOfRHBXGsTYwpRDwFWP56nKo2d2wBBTHDhCy6fb2dLW1fvSi/YspueOGIlHpvlYKi2/
CWqvs9xVrwcScMtiDoQYq0khhO0efLCxvg/o+W9CLMVM2ms4G1zoSUQKN0oYWWQJyW4+VI
YneWO8UpN0J3ElXKi7bhgAat7dBaM1g9IrAzk153DiEFZNsPxGOgL/+YdQN7zUBx/z7EkI
jyv80RV7fpUXvcq2p+qNl6UVig3VSzRrnsaJkUWu/A0u59ha7ocv6NxDIXjxpIDJme16GF
quiGVBQNnYJymS/vFEbGf6bgf7iRmMCRUMG4nqLA6fPYP9uAtch+CmDfVLZC/fIdC5AAAA
wQCDissV4zH6bfqgxJSuYNk8Vbb+19cF3b7gH1rVlB3zxpCAgcRgMHC+dP1z2NRx7UW9MR
nye6kjpkzZZ0OigLqo7TtEq8uTglD9o6W7mRXqhy5A/ySOmqPL3ernHHQhGuoNODYAHkOU
u2Rh8HXi+VLwKZcLInPOYJvcuLG4DxN8WfeVvlMHwhAOaTNNOtL4XZDHQeIPc4qHmJymmv
sV7GuyQ6yW5C10uoGdxRPd90Bh4z4h2bKfZFjvEBbSBVkqrlAAAADBAN/zNtNayd/dX7Cr
Nb4sZuzCh+CW4BH8GOePZWNCATwBbNXBVb5cR+dmuTqYm+Ekz0VxVQRA1TvKncluJOQpoa
Xj8r0xdIgqkehnfDPMKtYVor06B9Fl1jrXtXU0Vrr6QcBWruSVyK1ZxqcmcNK/+KolVepe
A6vcl/iKaG4U7su166nxLST06M2EgcSVsFJHpKn5+WAXC+X0Gx8kNjWIIb3GpiChdc0xZD
mq02xZthVJrTCVw/e7gfDoB2QRsNV8HwAAAMEAzsCghZVp+0YsYg9oOrw4tEqcbEXEMhwY
0jW8JNL8Spr1Ibp5Dw6bRSk5azARjmJtnMJhJ3oeHfF0eoISqcNuQXGndGQbVM9YzzAzc1
NbbCNsVroqKlChT5wyPNGS+phi2bPARBno7WSDvshTZ7dAVEP2c9MJW0XwoSevwKlhgSdt
RLFFQ/5nclJSdzPBOmQouC0OBcMFSrYtMeknJ4VvueVvve5HcHFaEsaMc7ABAGaLYaBQOm
iixITGvaNZh/tjAAAACW5pY29sYUBwMQE=
-----END OPENSSH PRIVATE KEY-----`
	// test CA user key.
	// % ssh-keygen -f ca_user_key
	testCAUserKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDF5fcwZHiyixmnE6IlOZJpZhWXoh62gN+yadAA0GJ509SAEaZVLPDP8S5RsE8mUikR3wxynVshxHeqMhrkS+RlNbhSlOXDdNg94yTrq/xF8Z/PgKRInvef74k5i7bAIytza7jERzFJ/ujTEy3537T5k5EYQJ15ZQGuvzynSdv+6o99SjI4jFplyQOZ2QcYbEAmhHm5GgQlIiEFG/RlDtLksOulKZxOY3qPzP0AyQxtZJXn/5vG40aW9LTbwxCJqWlgrkFXMqAAVCbuU5YspwhiXmKt1PsldiXw23oloa4caCKN1jzbFiGuZNXEU2Ebx7JIvjQCPaUYwLjEbkRDxDqN/vmwZqBuKYiuG9Eafx+nFSQkr7QYb5b+mT+/1IFHnmeRGn38731kBqtH7tpzC/t+soRX9p2HtJM+9MYhblO2OqTSPGTlxihWUkyiRBekpAhaiHld16TsG+A3bOJHrojGcX+5g6oGarKGLAMcykL1X+rZqT993Mo6d2Z7q43MOXE= root@p1"
	// this is testPubKey signed using testCAUserKey.
	// % ssh-keygen -s ca_user_key -I test_user_sftp -n test_user_sftp -V always:forever -O source-address=127.0.0.1 -z 1 /tmp/test.pub
	testCertValid = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgm2fil1IIoTixrA2QE9tk7Vbspj/JdEY90e3K2htxYv8AAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0AAAAAAAAAAQAAAAEAAAAOdGVzdF91c2VyX3NmdHAAAAASAAAADnRlc3RfdXNlcl9zZnRwAAAAAAAAAAD//////////wAAACMAAAAOc291cmNlLWFkZHJlc3MAAAANAAAACTEyNy4wLjAuMQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAMXl9zBkeLKLGacToiU5kmlmFZeiHraA37Jp0ADQYnnT1IARplUs8M/xLlGwTyZSKRHfDHKdWyHEd6oyGuRL5GU1uFKU5cN02D3jJOur/EXxn8+ApEie95/viTmLtsAjK3NruMRHMUn+6NMTLfnftPmTkRhAnXllAa6/PKdJ2/7qj31KMjiMWmXJA5nZBxhsQCaEebkaBCUiIQUb9GUO0uSw66UpnE5jeo/M/QDJDG1klef/m8bjRpb0tNvDEImpaWCuQVcyoABUJu5TliynCGJeYq3U+yV2JfDbeiWhrhxoIo3WPNsWIa5k1cRTYRvHski+NAI9pRjAuMRuREPEOo3++bBmoG4piK4b0Rp/H6cVJCSvtBhvlv6ZP7/UgUeeZ5EaffzvfWQGq0fu2nML+36yhFf2nYe0kz70xiFuU7Y6pNI8ZOXGKFZSTKJEF6SkCFqIeV3XpOwb4Dds4keuiMZxf7mDqgZqsoYsAxzKQvVf6tmpP33cyjp3Znurjcw5cQAAAZQAAAAMcnNhLXNoYTItNTEyAAABgMNenD7d1J9cF7JWgHA1DYpJ5+5knPtdXbbIgZAznsTxX7qOdptjeeYOuzhQ5Bwklh3fjewiJpGR1rBqbULP+6PAKeYqd7dNLH/upfKBfJweRf5pdXDpoknHaVuIhi4Uu6FeI4NkAzX9nqNKjFAflhJ+7GLGkLNb0UVZxgxr/t0rPmxc5iTg2ZRM+rk1Ij0S5RnGiKVsdAClqNA6h4TDzu5lJVdK5XvuNKBsKVRCvsVBOgJQTtRTLywQaqWR+HBfCiMj8X8EI7atDlJ6XIAlTLOO/f1sM8QPLjT0+tCHZaGFzg/lKPh3/yFQ4MvddZCptMy1Ll1xvj7cz2ynhGR4PiDfikV3YzgJU/KtL5y+ZB4jU08oPRiOP612PjwZZ+MqYOVOFCKUpMpZQs5UJHME+zNKr4LEj8M0x4YFKIciC+RsrCo4ujbJHmz61ionCadU+fmngvl3C3QjmUdgULBevODeUeIpJv4yFahNxrG1SKRTAa8VVDwJ9GdDTtmXM0mrwA== nicola@p1"
	// this is testPubKey signed using a CA user key different from testCAUserKey
	testCertUntrustedCA = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg8oFPWpjYy/DowMmtOjWj7Dq20d2N/4Rxzr/c710tOOUAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0AAAAAAAAAAAAAAAEAAAAOdGVzdF91c2VyX3NmdHAAAAASAAAADnRlc3RfdXNlcl9zZnRwAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQCqgm2gVlptULThfpRR0oCb4SAU3368ULlJaiZOUdq6b94KTfgmu4hTLs7u3a8hyZnVxrKrJ93uAVCwa/HGtgiN96CNC6JUt/QnPqTJ8LQ207RdoE9fbOe6mGwOle5z45+5JFoIi5ZZuD8JsBGodVoa92UepoMyBcNtZyl9q2GP4yT2tIYRon79dtG9AXiDYyhSgePqaObN67dn3ivMc4ZGNukK3cG07cYPic5y0wxX16wSMG3pGQDyUkAu+s4AqpnV9EWHM4PE7SYkCXE99++tUK3QALYqvGZKrLHgzmDKi6n+e14vHYUppAeGDZzwlawiY4oGP9eOW2KUfjZe2ZeL22JTFDYzH2lNV2WtUpeKRGGTSGaUblRVC9hRt6hKCT4c7qpW4kO4kPhE39JpcNPGLql7srNkw+3xXBs8xghMPtH3nOl1Rz2mxnX5tAqmPBb+KiPepnrs+pBRu7i+nCVp8az+iN87STYHy+zPtvTR+QURC8BpNraPOfXwpwM2HaMAAAGUAAAADHJzYS1zaGEyLTUxMgAAAYBnTXCL6tXUO3/Gtsm7lnH9Sulzca8FOoI4Y/4bVYhq4iUNu7Ca452m+Xr9qmCEoIyIJF0LEEcJ8jcS4rfX15e7tNNoknv7JbYXBFAbp1Y/76iqVf89FjfVcbEyH2ToAf7eyQAWzQ3gEKS8mQIkLnAwmCboUXC4GRodSIiOXiTt5Q6T02MVc8TxkhmlTA0uVLd5XgstySgE/oLBnL59lhJcwQmdhHL+m480+PaW55CtMuC36RTwk/tOyuWCDC5qMXnoveNB3yu45o3L/U4hoyJ0/5FyP5C8ahgydY0LoRZQG/mNzuraY4433rK+IfkQvZTyaDtcjhxE6hCD5F40aDDh88i6XaKAPikD6fqra6BN8PoPgLuRHzOJuqsMXBWM99s7qPgSnBbmXlekz/1jvvFiCh3zvAFTxFz2KyE4+SbDcCrhpxkNL7idw6r/ZsHaI/2+zhDcgSs5MgBwYLJEj6zUqVdp5XsF8YfC7yNZV5/qy68qY2+zXrC57SPifU2SCPE= nicola@p1"
	// this is testPubKey signed as host certificate.
	// % ssh-keygen -s ca_user_key -I test_user_sftp -h -n test_user_sftp -V always:forever -z 2 /tmp/test.pub
	testHostCert = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg7O2LDpLO1jGTX3SSzEMILoAYJb9DdggyyaUMXUUg3L4AAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0AAAAAAAAAAgAAAAIAAAAOdGVzdF91c2VyX3NmdHAAAAASAAAADnRlc3RfdXNlcl9zZnRwAAAAAAAAAAD//////////wAAAAAAAAAAAAAAAAAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAMXl9zBkeLKLGacToiU5kmlmFZeiHraA37Jp0ADQYnnT1IARplUs8M/xLlGwTyZSKRHfDHKdWyHEd6oyGuRL5GU1uFKU5cN02D3jJOur/EXxn8+ApEie95/viTmLtsAjK3NruMRHMUn+6NMTLfnftPmTkRhAnXllAa6/PKdJ2/7qj31KMjiMWmXJA5nZBxhsQCaEebkaBCUiIQUb9GUO0uSw66UpnE5jeo/M/QDJDG1klef/m8bjRpb0tNvDEImpaWCuQVcyoABUJu5TliynCGJeYq3U+yV2JfDbeiWhrhxoIo3WPNsWIa5k1cRTYRvHski+NAI9pRjAuMRuREPEOo3++bBmoG4piK4b0Rp/H6cVJCSvtBhvlv6ZP7/UgUeeZ5EaffzvfWQGq0fu2nML+36yhFf2nYe0kz70xiFuU7Y6pNI8ZOXGKFZSTKJEF6SkCFqIeV3XpOwb4Dds4keuiMZxf7mDqgZqsoYsAxzKQvVf6tmpP33cyjp3Znurjcw5cQAAAZQAAAAMcnNhLXNoYTItNTEyAAABgHlAWMTTzNrE6pxHlkr09ZXsHgJi8U2p7eifs56DOLgklYIXVUJPEEcnzMKGdpPBnqJsvg3+PccqxgOr5L1dFuOmekQ/dGiHd1enrESiGvJOvDfm0WsuBjxEZkSNFWgC9Z2NltToMmRlhVBmb4ZRZtAmi9DAFlJ/BDV4t8ikXZ5oUsigwIeOeLkdPFx3C3x9KZIpuwuAIV4Nfmz75q1NMWY2K1hv682QCKwMYqOWSotz1vWunNmZ0yPRl9UwqAq+nqwO3AApnlrQ3MmHujWQ5tl65PyhfpI8oghhUtB6YrJIAuRXNI/S0+KewCpiYm7nbFBtv9lpecujxAeTibYBrFZ5VODEUm3sdQ/HMdTmkhi6xNgPDQVlvKFqBJAaqoO3tbhKTbEZ865tJMqhyxmZ4XY08wduvSVobrNr7s3rm42/FXLIpung+UOVXonHyeIv9zQ0iJ/bvqKQ1fOsTisZdcD0lz80ZGsjdgJt7yKfUNBnAyVbTXm048E3WsZslJIYCA== nicola@p1"
	// this is testPubKey signed using testCAUserKey but with source address 172.16.34.45.
	// % ssh-keygen -s ca_user_key -I test_user_sftp -n test_user_sftp -V always:forever -O source-address=172.16.34.45 -z 3 /tmp/test.pub
	testCertOtherSourceAddress = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgZ4Su0250R4sQRNYJqJH9VTp9OyeYMAvqY5+lJRI4LzMAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0AAAAAAAAAAwAAAAEAAAAOdGVzdF91c2VyX3NmdHAAAAASAAAADnRlc3RfdXNlcl9zZnRwAAAAAAAAAAD//////////wAAACYAAAAOc291cmNlLWFkZHJlc3MAAAAQAAAADDE3Mi4xNi4zNC40NQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAMXl9zBkeLKLGacToiU5kmlmFZeiHraA37Jp0ADQYnnT1IARplUs8M/xLlGwTyZSKRHfDHKdWyHEd6oyGuRL5GU1uFKU5cN02D3jJOur/EXxn8+ApEie95/viTmLtsAjK3NruMRHMUn+6NMTLfnftPmTkRhAnXllAa6/PKdJ2/7qj31KMjiMWmXJA5nZBxhsQCaEebkaBCUiIQUb9GUO0uSw66UpnE5jeo/M/QDJDG1klef/m8bjRpb0tNvDEImpaWCuQVcyoABUJu5TliynCGJeYq3U+yV2JfDbeiWhrhxoIo3WPNsWIa5k1cRTYRvHski+NAI9pRjAuMRuREPEOo3++bBmoG4piK4b0Rp/H6cVJCSvtBhvlv6ZP7/UgUeeZ5EaffzvfWQGq0fu2nML+36yhFf2nYe0kz70xiFuU7Y6pNI8ZOXGKFZSTKJEF6SkCFqIeV3XpOwb4Dds4keuiMZxf7mDqgZqsoYsAxzKQvVf6tmpP33cyjp3Znurjcw5cQAAAZQAAAAMcnNhLXNoYTItNTEyAAABgL34Q3Li8AJIxZLU+fh4i8ehUWpm31vEvlNjXVCeP70xI+5hWuEt6E1TgKw7GCL5GeD4KehX4vVcNs+A2eOdIUZfDBZIFxn88BN8xcMlDpAMJXgvNqGttiOwcspL6X3N288djUgpCI718lLRdz8nvFqcuYBhSpBm5KL4JzH5o1o8yqv75wMJsH8CJYwGhvWi0OgWOqaLRAk3IUxq3Fbgo/nX11NgrkY/dHIZCkGBFaLJ/M5mfmt/K/5hJAVgLcSxMwB/ryyGaziB9Pv7CwZ9uwnMoRcAvyr96lqgdtLt7LNY8ktugAJ7EnBWjQn4+EJAjjRK2sCaiwpdP37ckDZgmk0OWGEL1yVy8VXgl9QBd7Mb1EVl+lhRyw8jlgBXZOGqpdDrmKCdBYGtU7ujyndLXmxZEAlqhef0yCsyZPTkYH3RhjCYs8ATrEqndEpiL59Nej5uUGQURYijJfHep08AMb4rCxvIZATVm1Ocxu48rGCGolv8jZFJzSJq84HCrVRKMw== nicola@p1"
	// this is testPubKey signed using testCAUserKey but expired.
	// % ssh-keygen -s ca_user_key -I test_user_sftp -n test_user_sftp -V 20100101123000:20110101123000 -z 4 /tmp/test.pub
	testCertExpired = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgU3TLP5285k20fBSsdZioI78oJUpaRXFlgx5IPg6gWg8AAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0AAAAAAAAABAAAAAEAAAAOdGVzdF91c2VyX3NmdHAAAAASAAAADnRlc3RfdXNlcl9zZnRwAAAAAEs93LgAAAAATR8QOAAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDF5fcwZHiyixmnE6IlOZJpZhWXoh62gN+yadAA0GJ509SAEaZVLPDP8S5RsE8mUikR3wxynVshxHeqMhrkS+RlNbhSlOXDdNg94yTrq/xF8Z/PgKRInvef74k5i7bAIytza7jERzFJ/ujTEy3537T5k5EYQJ15ZQGuvzynSdv+6o99SjI4jFplyQOZ2QcYbEAmhHm5GgQlIiEFG/RlDtLksOulKZxOY3qPzP0AyQxtZJXn/5vG40aW9LTbwxCJqWlgrkFXMqAAVCbuU5YspwhiXmKt1PsldiXw23oloa4caCKN1jzbFiGuZNXEU2Ebx7JIvjQCPaUYwLjEbkRDxDqN/vmwZqBuKYiuG9Eafx+nFSQkr7QYb5b+mT+/1IFHnmeRGn38731kBqtH7tpzC/t+soRX9p2HtJM+9MYhblO2OqTSPGTlxihWUkyiRBekpAhaiHld16TsG+A3bOJHrojGcX+5g6oGarKGLAMcykL1X+rZqT993Mo6d2Z7q43MOXEAAAGUAAAADHJzYS1zaGEyLTUxMgAAAYAlH3hhj8J6xLyVpeLZjblzwDKrxp/MWiH30hQ965ExPrPRcoAZFEKVqOYdj6bp4Q19Q4Yzqdobg3aN5ym2iH0b2TlOY0mM901CAoHbNJyiLs+0KiFRoJ+30EDj/hcKusg6v8ln2yixPagAyQu3zyiWo4t1ZuO3I86xchGlptStxSdHAHPFCfpbhcnzWFZctiMqUutl82C4ROWyjOZcRzdVdWHeN5h8wnooXuvba2VkT8QPmjYYyRGuQ3Hg+ySdh8Tel4wiix1Dg5MX7Wjh4hKEx80No9UPy+0iyZMNc07lsWAtrY6NRxGM5CzB6mklscB8TzFrVSnIl9u3bquLfaCrFt/Mft5dR7Yy4jmF+zUhjia6h6giCZ91J+FZ4hV+WkBtPCvTfrGWoA1BgEB/iI2xOq/NPqJ7UXRoMXk/l0NPgRPT2JS1adegqnt4ddr6IlmPyZxaSEvXhanjKdfMlEFYO1wz7ouqpYUozQVy4KXBlzFlNwyD1hI+k4+/A6AIYeI= nicola@p1"
	// this is testPubKey signed without a principal
	// ssh-keygen -s ca_user_key -I test_user_sftp -V always:forever -O source-address=127.0.0.1 -z 1 /tmp/test.pub
	testCertNoPrincipals = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg2Bx0s8nafJtriqoBuQfbFByhdQMkjDIZhV90JZSGN8AAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0AAAAAAAAAAQAAAAEAAAAOdGVzdF91c2VyX3NmdHAAAAAAAAAAAAAAAAD//////////wAAACMAAAAOc291cmNlLWFkZHJlc3MAAAANAAAACTEyNy4wLjAuMQAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAMXl9zBkeLKLGacToiU5kmlmFZeiHraA37Jp0ADQYnnT1IARplUs8M/xLlGwTyZSKRHfDHKdWyHEd6oyGuRL5GU1uFKU5cN02D3jJOur/EXxn8+ApEie95/viTmLtsAjK3NruMRHMUn+6NMTLfnftPmTkRhAnXllAa6/PKdJ2/7qj31KMjiMWmXJA5nZBxhsQCaEebkaBCUiIQUb9GUO0uSw66UpnE5jeo/M/QDJDG1klef/m8bjRpb0tNvDEImpaWCuQVcyoABUJu5TliynCGJeYq3U+yV2JfDbeiWhrhxoIo3WPNsWIa5k1cRTYRvHski+NAI9pRjAuMRuREPEOo3++bBmoG4piK4b0Rp/H6cVJCSvtBhvlv6ZP7/UgUeeZ5EaffzvfWQGq0fu2nML+36yhFf2nYe0kz70xiFuU7Y6pNI8ZOXGKFZSTKJEF6SkCFqIeV3XpOwb4Dds4keuiMZxf7mDqgZqsoYsAxzKQvVf6tmpP33cyjp3Znurjcw5cQAAAZQAAAAMcnNhLXNoYTItNTEyAAABgHgax/++NA5YZXDHH180BcQtDBve8Vc+XJzqQUe8xBiqd+KJnas6He7vW62qMaAfu63i0Uycj2Djfjy5dyx1GB9wup8YuP5mXlmJTx+7UPPjwbfrZWtk8iJ7KhFAwjh0KRZD4uIvoeecK8QE9zh64k2LNVqlWbFTdoPulRC29cGcXDpMU2eToFEyWbceHOZyyifXf98ZMZbaQzWzwSZ5rFucJ1b0aeT6aAJWB+Dq7mIQWf/jCWr8kNaeCzMKJsFQkQEfmHls29ChV92sNRhngUDxll0Ir0wpPea1fFEBnUhLRTLC8GhDDbWAzsZtXqx9fjoAkb/gwsU6TGxevuOMxEABjDA9PyJiTXJI9oTUCwDIAUVVFLsCEum3o/BblngXajUGibaif5ZSKBocpP70oTeAngQYB7r1/vquQzGsGFhTN4FUXLSpLu9Zqi1z58/qa7SgKSfNp98X/4zrhltAX73ZEvg0NUMv2HwlwlqHdpF3FYolAxInp7c2jBTncQ2l3w== nicola@p1"
	configDir            = ".."
	osWindows            = "windows"
	testFileName         = "test_file_sftp.dat"
	testDLFileName       = "test_download_sftp.dat"
)

var (
	allPerms         = []string{dataprovider.PermAny}
	homeBasePath     string
	scpPath          string
	gitPath          string
	sshPath          string
	hookCmdPath      string
	pubKeyPath       string
	privateKeyPath   string
	trustedCAUserKey string
	revokeUserCerts  string
	gitWrapPath      string
	extAuthPath      string
	keyIntAuthPath   string
	preLoginPath     string
	postConnectPath  string
	preDownloadPath  string
	preUploadPath    string
	checkPwdPath     string
	logFilePath      string
	hostKeyFPs       []string
)

func TestMain(m *testing.M) {
	logFilePath = filepath.Join(configDir, "sftpgo_sftpd_test.log")
	loginBannerFileName := "login_banner"
	loginBannerFile := filepath.Join(configDir, loginBannerFileName)
	logger.InitLogger(logFilePath, 5, 1, 28, false, false, zerolog.DebugLevel)
	err := os.WriteFile(loginBannerFile, []byte("simple login banner\n"), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error creating login banner: %v", err)
	}
	os.Setenv("SFTPGO_COMMON__UPLOAD_MODE", "2")
	os.Setenv("SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN", "1")
	os.Setenv("SFTPGO_DEFAULT_ADMIN_USERNAME", "admin")
	os.Setenv("SFTPGO_DEFAULT_ADMIN_PASSWORD", "password")
	err = config.LoadConfig(configDir, "")
	if err != nil {
		logger.ErrorToConsole("error loading configuration: %v", err)
		os.Exit(1)
	}
	providerConf := config.GetProviderConf()
	logger.InfoToConsole("Starting SFTPD tests, provider: %v", providerConf.Driver)

	commonConf := config.GetCommonConfig()
	homeBasePath = os.TempDir()
	checkSystemCommands()
	var scriptArgs string
	if runtime.GOOS == osWindows {
		scriptArgs = "%*"
	} else {
		commonConf.Actions.ExecuteOn = []string{"download", "upload", "rename", "delete", "ssh_cmd",
			"pre-download", "pre-upload"}
		commonConf.Actions.Hook = hookCmdPath
		scriptArgs = "$@"
	}

	err = common.Initialize(commonConf, 0)
	if err != nil {
		logger.WarnToConsole("error initializing common: %v", err)
		os.Exit(1)
	}

	err = dataprovider.Initialize(providerConf, configDir, true)
	if err != nil {
		logger.ErrorToConsole("error initializing data provider: %v", err)
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

	sftpdConf := config.GetSFTPDConfig()
	httpdConf := config.GetHTTPDConfig()
	sftpdConf.Bindings = []sftpd.Binding{
		{
			Port:             2022,
			ApplyProxyConfig: true,
		},
	}
	sftpdConf.KexAlgorithms = []string{"curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384"}
	sftpdConf.Ciphers = []string{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com",
		"aes256-ctr"}
	sftpdConf.MACs = []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"}
	sftpdConf.LoginBannerFile = loginBannerFileName
	// we need to test all supported ssh commands
	sftpdConf.EnabledSSHCommands = []string{"*"}

	keyIntAuthPath = filepath.Join(homeBasePath, "keyintauth.sh")
	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing keyboard interactive script: %v", err)
		os.Exit(1)
	}
	sftpdConf.KeyboardInteractiveAuthentication = true
	sftpdConf.KeyboardInteractiveHook = keyIntAuthPath

	createInitialFiles(scriptArgs)
	sftpdConf.TrustedUserCAKeys = append(sftpdConf.TrustedUserCAKeys, trustedCAUserKey)
	sftpdConf.RevokedUserCertsFile = revokeUserCerts

	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start SFTP server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := httpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start HTTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(sftpdConf.Bindings[0].GetAddress())
	waitTCPListening(httpdConf.Bindings[0].GetAddress())

	sftpdConf.Bindings = []sftpd.Binding{
		{
			Port:             2222,
			ApplyProxyConfig: true,
		},
	}
	sftpdConf.PasswordAuthentication = false
	common.Config.ProxyProtocol = 1
	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v and proxy protocol %v",
			sftpdConf, common.Config.ProxyProtocol)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start SFTP server with proxy protocol 1: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(sftpdConf.Bindings[0].GetAddress())

	prefixedConf := sftpdConf
	prefixedConf.Bindings = []sftpd.Binding{
		{
			Port:             2226,
			ApplyProxyConfig: false,
		},
	}
	prefixedConf.PasswordAuthentication = true
	prefixedConf.FolderPrefix = "/prefix/files"
	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v and proxy protocol %v",
			prefixedConf, common.Config.ProxyProtocol)
		if err := prefixedConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start SFTP server with proxy protocol 2: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(prefixedConf.Bindings[0].GetAddress())

	sftpdConf.Bindings = []sftpd.Binding{
		{
			Port:             2224,
			ApplyProxyConfig: true,
		},
	}
	sftpdConf.PasswordAuthentication = true
	common.Config.ProxyProtocol = 2
	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v and proxy protocol %v",
			sftpdConf, common.Config.ProxyProtocol)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start SFTP server with proxy protocol 2: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(sftpdConf.Bindings[0].GetAddress())
	getHostKeysFingerprints(sftpdConf.HostKeys)

	exitCode := m.Run()
	os.Remove(logFilePath)
	os.Remove(loginBannerFile)
	os.Remove(pubKeyPath)
	os.Remove(privateKeyPath)
	os.Remove(trustedCAUserKey)
	os.Remove(revokeUserCerts)
	os.Remove(gitWrapPath)
	os.Remove(extAuthPath)
	os.Remove(preLoginPath)
	os.Remove(postConnectPath)
	os.Remove(preDownloadPath)
	os.Remove(preUploadPath)
	os.Remove(keyIntAuthPath)
	os.Remove(checkPwdPath)
	os.Exit(exitCode)
}

func TestInitialization(t *testing.T) {
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Bindings = []sftpd.Binding{
		{
			Port:             2022,
			ApplyProxyConfig: true,
		},
		{
			Port: 0,
		},
	}
	sftpdConf.LoginBannerFile = "invalid_file"
	sftpdConf.EnabledSSHCommands = append(sftpdConf.EnabledSSHCommands, "ls")
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.KeyboardInteractiveAuthentication = true
	sftpdConf.KeyboardInteractiveHook = "invalid_file"
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.KeyboardInteractiveHook = filepath.Join(homeBasePath, "invalid_file")
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.Bindings = []sftpd.Binding{
		{
			Port:             4444,
			ApplyProxyConfig: true,
		},
	}
	common.Config.ProxyProtocol = 1
	common.Config.ProxyAllowed = []string{"1270.0.0.1"}
	assert.True(t, sftpdConf.Bindings[0].HasProxy())
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.HostKeys = []string{"missing key"}
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.HostKeys = nil
	sftpdConf.TrustedUserCAKeys = []string{"missing ca key"}
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.Bindings = nil
	err = sftpdConf.Initialize(configDir)
	assert.EqualError(t, err, common.ErrNoBinding.Error())
	sftpdConf = config.GetSFTPDConfig()
	sftpdConf.Ciphers = []string{"not a cipher"}
	err = sftpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unsupported cipher")
	}
	sftpdConf.Ciphers = nil
	sftpdConf.MACs = []string{"not a MAC"}
	err = sftpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unsupported MAC algorithm")
	}
	sftpdConf.KexAlgorithms = []string{"not a KEX"}
	err = sftpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unsupported key-exchange algorithm")
	}
	sftpdConf.HostKeyAlgorithms = []string{"not a host key algo"}
	err = sftpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unsupported host key algorithm")
	}
	sftpdConf.HostKeyAlgorithms = nil
	sftpdConf.HostCertificates = []string{"missing file"}
	err = sftpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to load host certificate")
	}
	sftpdConf.HostCertificates = []string{"."}
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	hostCertPath := filepath.Join(os.TempDir(), "host_cert.pub")
	err = os.WriteFile(hostCertPath, []byte(testCertValid), 0600)
	assert.NoError(t, err)
	sftpdConf.HostKeys = []string{privateKeyPath}
	sftpdConf.HostCertificates = []string{hostCertPath}
	err = sftpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is not an host certificate")
	}
	err = os.WriteFile(hostCertPath, []byte(testPubKey), 0600)
	assert.NoError(t, err)
	err = sftpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is not an SSH certificate")
	}
	err = os.WriteFile(hostCertPath, []byte("abc"), 0600)
	assert.NoError(t, err)
	err = sftpdConf.Initialize(configDir)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to parse host certificate")
	}
	err = os.WriteFile(hostCertPath, []byte(testHostCert), 0600)
	assert.NoError(t, err)
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)

	err = os.Remove(hostCertPath)
	assert.NoError(t, err)
	sftpdConf.HostKeys = nil
	sftpdConf.HostCertificates = nil
	sftpdConf.RevokedUserCertsFile = "."
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.RevokedUserCertsFile = "a missing file"
	err = sftpdConf.Initialize(configDir)
	assert.ErrorIs(t, err, os.ErrNotExist)

	err = createTestFile(revokeUserCerts, 10*1024*1024)
	sftpdConf.RevokedUserCertsFile = revokeUserCerts
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)

	err = os.WriteFile(revokeUserCerts, []byte(`[]`), 0644)
	assert.NoError(t, err)
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
}

func TestBasicSFTPHandling(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaSize = 6553600
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		expectedQuotaSize := user.UsedQuotaSize + testFileSize
		expectedQuotaFiles := user.UsedQuotaFiles + 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join("/missing_dir", testFileName), testFileSize, client)
		assert.Error(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		_, err = client.Lstat(testFileName)
		assert.Error(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize-testFileSize, user.UsedQuotaSize)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	u.Username = "missing user"
	_, _, err = getSftpClient(u, false)
	assert.Error(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	status := sftpd.GetStatus()
	assert.True(t, status.IsActive)
	sshCommands := status.GetSSHCommandsAsString()
	assert.NotEmpty(t, sshCommands)
	sshAuths := status.GetSupportedAuthsAsString()
	assert.NotEmpty(t, sshAuths)
}

func TestBasicSFTPFsHandling(t *testing.T) {
	usePubKey := true
	baseUser, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	u := getTestSFTPUser(usePubKey)
	u.QuotaSize = 6553600
	u.FsConfig.SFTPConfig.DisableCouncurrentReads = true
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		testLinkName := testFileName + ".link"
		expectedQuotaSize := testFileSize
		expectedQuotaFiles := 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		err = client.Symlink(testFileName, testLinkName)
		assert.NoError(t, err)
		info, err := client.Lstat(testLinkName)
		if assert.NoError(t, err) {
			assert.True(t, info.Mode()&os.ModeSymlink != 0)
		}
		info, err = client.Stat(testLinkName)
		if assert.NoError(t, err) {
			assert.True(t, info.Mode()&os.ModeSymlink == 0)
		}
		val, err := client.ReadLink(testLinkName)
		if assert.NoError(t, err) {
			assert.Equal(t, path.Join("/", testFileName), val)
		}
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		_, err = client.Lstat(testFileName)
		assert.Error(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 0, user.UsedQuotaFiles)
		assert.Equal(t, int64(0), user.UsedQuotaSize)
		// now overwrite the symlink
		err = sftpUploadFile(testFilePath, testLinkName, testFileSize, client)
		assert.NoError(t, err)
		contents, err := client.ReadDir("/")
		if assert.NoError(t, err) {
			assert.Len(t, contents, 1)
			assert.Equal(t, testFileSize, contents[0].Size())
			assert.Equal(t, testLinkName, contents[0].Name())
			assert.False(t, contents[0].IsDir())
			assert.True(t, contents[0].Mode().IsRegular())
		}
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)

		stat, err := client.StatVFS("/")
		assert.NoError(t, err)
		assert.Equal(t, uint64(u.QuotaSize/4096), stat.Blocks)
		assert.Equal(t, uint64((u.QuotaSize-testFileSize)/4096), stat.Bfree)
		assert.Equal(t, uint64(1), stat.Files-stat.Ffree)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(baseUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(baseUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestStartDirectory(t *testing.T) {
	usePubKey := false
	startDir := "/st@ rt/dir"
	u := getTestUser(usePubKey)
	u.Filters.StartDirectory = startDir
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		currentDir, err := client.Getwd()
		assert.NoError(t, err)
		assert.Equal(t, startDir, currentDir)

		entries, err := client.ReadDir(".")
		assert.NoError(t, err)
		assert.Len(t, entries, 0)

		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		_, err = client.Stat(testFileName)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileName+"_rename")
		assert.NoError(t, err)

		entries, err = client.ReadDir(".")
		assert.NoError(t, err)
		assert.Len(t, entries, 1)

		currentDir, err = client.RealPath("..")
		assert.NoError(t, err)
		assert.Equal(t, path.Dir(startDir), currentDir)

		currentDir, err = client.RealPath("../..")
		assert.NoError(t, err)
		assert.Equal(t, "/", currentDir)

		currentDir, err = client.RealPath("../../..")
		assert.NoError(t, err)
		assert.Equal(t, "/", currentDir)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestFolderPrefix(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	conn, client, err := getSftpClientWithAddr(user, usePubKey, "127.0.0.1:2226")
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		_, err = client.Stat("path")
		assert.ErrorIs(t, err, os.ErrPermission)
		_, err = client.Stat("/prefix/path")
		assert.ErrorIs(t, err, os.ErrPermission)
		_, err = client.Stat("/prefix/files1")
		assert.ErrorIs(t, err, os.ErrPermission)
		contents, err := client.ReadDir("/")
		if assert.NoError(t, err) {
			if assert.Len(t, contents, 1) {
				assert.Equal(t, "prefix", contents[0].Name())
			}
		}
		contents, err = client.ReadDir("/prefix")
		if assert.NoError(t, err) {
			if assert.Len(t, contents, 1) {
				assert.Equal(t, "files", contents[0].Name())
			}
		}
		_, err = client.OpenFile(testFileName, os.O_WRONLY|os.O_CREATE)
		assert.ErrorIs(t, err, os.ErrPermission)
		_, err = client.OpenFile(testFileName, os.O_RDONLY)
		assert.ErrorIs(t, err, os.ErrPermission)

		f, err := client.OpenFile(path.Join("prefix", "files", testFileName), os.O_WRONLY|os.O_CREATE)
		assert.NoError(t, err)
		_, err = f.Write([]byte("test"))
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginNonExistentUser(t *testing.T) {
	usePubKey := true
	user := getTestUser(usePubKey)
	_, _, err := getSftpClient(user, usePubKey)
	assert.Error(t, err)
}

func TestRateLimiter(t *testing.T) {
	oldConfig := config.GetCommonConfig()

	cfg := config.GetCommonConfig()
	cfg.RateLimitersConfig = []common.RateLimiterConfig{
		{
			Average:   1,
			Period:    1000,
			Burst:     1,
			Type:      1,
			Protocols: []string{common.ProtocolSSH},
		},
	}

	err := common.Initialize(cfg, 0)
	assert.NoError(t, err)

	usePubKey := false
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}
	_, _, err = getSftpClient(user, usePubKey)
	assert.Error(t, err)

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

	err := common.Initialize(cfg, 0)
	assert.NoError(t, err)

	usePubKey := false
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	for i := 0; i < 3; i++ {
		user.Password = "wrong_pwd"
		_, _, err = getSftpClient(user, usePubKey)
		assert.Error(t, err)
	}

	user.Password = defaultPassword
	_, _, err = getSftpClient(user, usePubKey)
	assert.Error(t, err)

	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = common.Initialize(oldConfig, 0)
	assert.NoError(t, err)
}

func TestOpenReadWrite(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaSize = 6553600
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	u.QuotaSize = 6553600
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			sftpFile, err := client.OpenFile(testFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
			if assert.NoError(t, err) {
				testData := []byte("sample test data")
				n, err := sftpFile.Write(testData)
				assert.NoError(t, err)
				assert.Equal(t, len(testData), n)
				buffer := make([]byte, 128)
				n, err = sftpFile.ReadAt(buffer, 1)
				assert.EqualError(t, err, io.EOF.Error())
				assert.Equal(t, len(testData)-1, n)
				assert.Equal(t, testData[1:], buffer[:n])
				err = sftpFile.Close()
				assert.NoError(t, err)
			}
			sftpFile, err = client.OpenFile(testFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
			if assert.NoError(t, err) {
				testData := []byte("new test data")
				n, err := sftpFile.Write(testData)
				assert.NoError(t, err)
				assert.Equal(t, len(testData), n)
				buffer := make([]byte, 128)
				n, err = sftpFile.ReadAt(buffer, 1)
				assert.EqualError(t, err, io.EOF.Error())
				assert.Equal(t, len(testData)-1, n)
				assert.Equal(t, testData[1:], buffer[:n])
				err = sftpFile.Close()
				assert.NoError(t, err)
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

func TestOpenReadWritePerm(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	// we cannot read inside "/sub", rename is needed otherwise the atomic upload will fail for the sftpfs user
	u.Permissions["/sub"] = []string{dataprovider.PermUpload, dataprovider.PermListItems, dataprovider.PermRename}
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	u.Permissions["/sub"] = []string{dataprovider.PermUpload, dataprovider.PermListItems}
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			err = client.Mkdir("sub")
			assert.NoError(t, err)
			sftpFileName := path.Join("sub", "file.txt")
			sftpFile, err := client.OpenFile(sftpFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
			if assert.NoError(t, err) {
				testData := []byte("test data")
				n, err := sftpFile.Write(testData)
				assert.NoError(t, err)
				assert.Equal(t, len(testData), n)
				buffer := make([]byte, 128)
				_, err = sftpFile.ReadAt(buffer, 1)
				if assert.Error(t, err) {
					assert.Contains(t, strings.ToLower(err.Error()), "permission denied")
				}
				err = sftpFile.Close()
				assert.NoError(t, err)
			}
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

func TestConcurrency(t *testing.T) {
	oldValue := common.Config.MaxPerHostConnections
	common.Config.MaxPerHostConnections = 0

	usePubKey := true
	numLogins := 50
	u := getTestUser(usePubKey)
	u.QuotaFiles = numLogins + 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	var wg sync.WaitGroup
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(262144)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	closedConns := int32(0)
	for i := 0; i < numLogins; i++ {
		wg.Add(1)
		go func(counter int) {
			defer wg.Done()
			defer atomic.AddInt32(&closedConns, 1)

			conn, client, err := getSftpClient(user, usePubKey)
			if assert.NoError(t, err) {
				err = checkBasicSFTP(client)
				assert.NoError(t, err)
				err = sftpUploadFile(testFilePath, testFileName+strconv.Itoa(counter), testFileSize, client)
				assert.NoError(t, err)
				assert.Greater(t, common.Connections.GetActiveSessions(defaultUsername), 0)
				client.Close()
				conn.Close()
			}
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		maxConns := 0
		maxSessions := 0
		for {
			servedReqs := atomic.LoadInt32(&closedConns)
			if servedReqs > 0 {
				stats := common.Connections.GetStats()
				if len(stats) > maxConns {
					maxConns = len(stats)
				}
				activeSessions := common.Connections.GetActiveSessions(defaultUsername)
				if activeSessions > maxSessions {
					maxSessions = activeSessions
				}
			}
			if servedReqs >= int32(numLogins) {
				break
			}
			time.Sleep(1 * time.Millisecond)
		}
		assert.Greater(t, maxConns, 0)
		assert.Greater(t, maxSessions, 0)
	}()

	wg.Wait()

	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		files, err := client.ReadDir(".")
		assert.NoError(t, err)
		assert.Len(t, files, numLogins)
		client.Close()
		conn.Close()
	}

	assert.Eventually(t, func() bool {
		return common.Connections.GetActiveSessions(defaultUsername) == 0
	}, 1*time.Second, 50*time.Millisecond)

	assert.Eventually(t, func() bool {
		return len(common.Connections.GetStats()) == 0
	}, 1*time.Second, 50*time.Millisecond)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.MaxPerHostConnections = oldValue
}

func TestProxyProtocol(t *testing.T) {
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	// remove the home dir to test auto creation
	err = os.RemoveAll(user.HomeDir)
	assert.NoError(t, err)
	conn, client, err := getSftpClientWithAddr(user, usePubKey, sftpSrvAddr2222)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	conn, client, err = getSftpClientWithAddr(user, usePubKey, "127.0.0.1:2224")
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRealPath(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		p, err := client.RealPath("../..")
		assert.NoError(t, err)
		assert.Equal(t, "/", p)
		p, err = client.RealPath("../test")
		assert.NoError(t, err)
		assert.Equal(t, "/test", p)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestBufferedSFTP(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	u.FsConfig.SFTPConfig.BufferSize = 2
	u.HomeDir = filepath.Join(os.TempDir(), u.Username)
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(sftpUser, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		appendDataSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		initialHash, err := computeHashForFile(sha256.New(), testFilePath)
		assert.NoError(t, err)

		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = appendToTestFile(testFilePath, appendDataSize)
		assert.NoError(t, err)
		err = sftpUploadResumeFile(testFilePath, testFileName, testFileSize+appendDataSize, false, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
		}
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		downloadedFileHash, err := computeHashForFile(sha256.New(), localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, initialHash, downloadedFileHash)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)

		sftpFile, err := client.OpenFile(testFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
		if assert.NoError(t, err) {
			testData := []byte("sample test sftp data")
			n, err := sftpFile.Write(testData)
			assert.NoError(t, err)
			assert.Equal(t, len(testData), n)
			err = sftpFile.Truncate(0)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
			}
			err = sftpFile.Truncate(4)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
			}
			buffer := make([]byte, 128)
			_, err = sftpFile.Read(buffer)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "SSH_FX_OP_UNSUPPORTED")
			}
			err = sftpFile.Close()
			assert.NoError(t, err)
			info, err := client.Stat(testFileName)
			if assert.NoError(t, err) {
				assert.Equal(t, int64(len(testData)), info.Size())
			}
		}
		// test WriteAt
		sftpFile, err = client.OpenFile(testFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
		if assert.NoError(t, err) {
			testData := []byte("hello world")
			n, err := sftpFile.WriteAt(testData[:6], 0)
			assert.NoError(t, err)
			assert.Equal(t, 6, n)
			n, err = sftpFile.WriteAt(testData[6:], 6)
			assert.NoError(t, err)
			assert.Equal(t, 5, n)
			err = sftpFile.Close()
			assert.NoError(t, err)
			info, err := client.Stat(testFileName)
			if assert.NoError(t, err) {
				assert.Equal(t, int64(len(testData)), info.Size())
			}
		}
		// test ReadAt
		sftpFile, err = client.OpenFile(testFileName, os.O_RDONLY)
		if assert.NoError(t, err) {
			buffer := make([]byte, 128)
			n, err := sftpFile.ReadAt(buffer, 6)
			assert.ErrorIs(t, err, io.EOF)
			assert.Equal(t, 5, n)
			assert.Equal(t, []byte("world"), buffer[:n])
			err = sftpFile.Close()
			assert.NoError(t, err)
		}
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

func TestUploadResume(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(65535)
			appendDataSize := int64(65535)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			err = appendToTestFile(testFilePath, appendDataSize)
			assert.NoError(t, err)
			err = sftpUploadResumeFile(testFilePath, testFileName, testFileSize+appendDataSize, false, client)
			assert.NoError(t, err)
			localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
			err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize+appendDataSize, client)
			assert.NoError(t, err)
			initialHash, err := computeHashForFile(sha256.New(), testFilePath)
			assert.NoError(t, err)
			downloadedFileHash, err := computeHashForFile(sha256.New(), localDownloadPath)
			assert.NoError(t, err)
			assert.Equal(t, initialHash, downloadedFileHash)
			err = sftpUploadResumeFile(testFilePath, testFileName, testFileSize+appendDataSize, true, client)
			assert.Error(t, err, "resume uploading file with invalid offset must fail")
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
}

func TestDirCommands(t *testing.T) {
	usePubKey := false
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	// remove the home dir to test auto creation
	err = os.RemoveAll(user.HomeDir)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.Mkdir("test1")
		assert.NoError(t, err)
		err = client.Rename("test1", "test")
		assert.NoError(t, err)
		// rename a missing file
		err = client.Rename("test1", "test2")
		assert.Error(t, err)
		_, err = client.Lstat("/test1")
		assert.Error(t, err, "stat for renamed dir must not succeed")
		err = client.PosixRename("test", "test1")
		assert.NoError(t, err)
		err = client.Remove("test1")
		assert.NoError(t, err)
		err = client.Mkdir("/test/test1")
		assert.Error(t, err, "recursive mkdir must fail")
		err = client.Mkdir("/test")
		assert.NoError(t, err)
		err = client.Mkdir("/test/test1")
		assert.NoError(t, err)
		_, err = client.ReadDir("/this/dir/does/not/exist")
		assert.Error(t, err, "reading a missing dir must fail")
		err = client.RemoveDirectory("/test/test1")
		assert.NoError(t, err)
		err = client.RemoveDirectory("/test")
		assert.NoError(t, err)
		_, err = client.Lstat("/test")
		assert.Error(t, err, "stat for deleted dir must not succeed")
		_, err = client.Stat("/test")
		assert.Error(t, err, "stat for deleted dir must not succeed")
		err = client.RemoveDirectory("/test")
		assert.Error(t, err, "remove missing path must fail")
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRemove(t *testing.T) {
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.Mkdir("test")
		assert.NoError(t, err)
		err = client.Mkdir("/test/test1")
		assert.NoError(t, err)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join("/test", testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = client.Remove("/test")
		assert.Error(t, err, "remove non empty dir must fail")
		err = client.RemoveDirectory(path.Join("/test", testFileName))
		assert.Error(t, err, "remove a file with rmdir must fail")
		err = client.Remove(path.Join("/test", testFileName))
		assert.NoError(t, err)
		err = client.Remove(path.Join("/test", testFileName))
		assert.Error(t, err, "remove missing file must fail")
		err = client.Remove("/test/test1")
		assert.NoError(t, err)
		err = client.Remove("/test")
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLink(t *testing.T) {
	usePubKey := false
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		linkName, err := client.ReadLink(testFileName + ".link")
		assert.NoError(t, err)
		assert.Equal(t, path.Join("/", testFileName), linkName)
		err = client.Symlink(testFileName, testFileName+".link")
		assert.Error(t, err, "creating a symlink to an existing one must fail")
		err = client.Link(testFileName, testFileName+".hlink")
		assert.Error(t, err, "hard link is not supported and must fail")
		err = client.Remove(testFileName + ".link")
		assert.NoError(t, err)
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestStat(t *testing.T) {
	usePubKey := false
	localUser, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(65535)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			_, err := client.Lstat(testFileName)
			assert.NoError(t, err)
			_, err = client.Stat(testFileName)
			assert.NoError(t, err)
			// stat a missing path we should get an os.IsNotExist error
			_, err = client.Stat("missing path")
			assert.True(t, os.IsNotExist(err))
			_, err = client.Lstat("missing path")
			assert.True(t, os.IsNotExist(err))
			// mode 0666 and 0444 works on Windows too
			newPerm := os.FileMode(0666)
			err = client.Chmod(testFileName, newPerm)
			assert.NoError(t, err)
			newFi, err := client.Lstat(testFileName)
			assert.NoError(t, err)
			assert.Equal(t, newPerm, newFi.Mode().Perm())
			newPerm = os.FileMode(0444)
			err = client.Chmod(testFileName, newPerm)
			assert.NoError(t, err)
			newFi, err = client.Lstat(testFileName)
			if assert.NoError(t, err) {
				assert.Equal(t, newPerm, newFi.Mode().Perm())
			}
			_, err = client.ReadLink(testFileName)
			assert.Error(t, err, "readlink on a file must fail")
			symlinkName := testFileName + ".sym"
			err = client.Symlink(testFileName, symlinkName)
			assert.NoError(t, err)
			info, err := client.Lstat(symlinkName)
			if assert.NoError(t, err) {
				assert.True(t, info.Mode()&os.ModeSymlink != 0)
			}
			info, err = client.Stat(symlinkName)
			if assert.NoError(t, err) {
				assert.False(t, info.Mode()&os.ModeSymlink != 0)
			}
			linkName, err := client.ReadLink(symlinkName)
			assert.NoError(t, err)
			assert.Equal(t, path.Join("/", testFileName), linkName)
			newPerm = os.FileMode(0666)
			err = client.Chmod(testFileName, newPerm)
			assert.NoError(t, err)
			err = client.Truncate(testFileName, 100)
			assert.NoError(t, err)
			fi, err := client.Stat(testFileName)
			if assert.NoError(t, err) {
				assert.Equal(t, int64(100), fi.Size())
			}
			f, err := client.OpenFile(testFileName, os.O_WRONLY)
			if assert.NoError(t, err) {
				err = f.Truncate(5)
				assert.NoError(t, err)
				err = f.Close()
				assert.NoError(t, err)
			}
			f, err = client.OpenFile(testFileName, os.O_WRONLY)
			newPerm = os.FileMode(0444)
			if assert.NoError(t, err) {
				err = f.Chmod(newPerm)
				assert.NoError(t, err)
				err = f.Close()
				assert.NoError(t, err)
			}
			newFi, err = client.Lstat(testFileName)
			if assert.NoError(t, err) {
				assert.Equal(t, newPerm, newFi.Mode().Perm())
			}
			newPerm = os.FileMode(0666)
			err = client.Chmod(testFileName, newPerm)
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

func TestStatChownChmod(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("chown is not supported on Windows, chmod is partially supported")
	}
	usePubKey := true
	localUser, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(65535)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			err = client.Chown(testFileName, os.Getuid(), os.Getgid())
			assert.NoError(t, err)
			newPerm := os.FileMode(0600)
			err = client.Chmod(testFileName, newPerm)
			assert.NoError(t, err)
			newFi, err := client.Lstat(testFileName)
			assert.NoError(t, err)
			assert.Equal(t, newPerm, newFi.Mode().Perm())
			err = client.Remove(testFileName)
			assert.NoError(t, err)
			err = client.Chmod(testFileName, newPerm)
			assert.EqualError(t, err, os.ErrNotExist.Error())
			err = client.Chown(testFileName, os.Getuid(), os.Getgid())
			assert.EqualError(t, err, os.ErrNotExist.Error())
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

func TestSFTPFsLoginWrongFingerprint(t *testing.T) {
	usePubKey := true
	localUser, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(sftpUser, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	sftpUser.FsConfig.SFTPConfig.Fingerprints = append(sftpUser.FsConfig.SFTPConfig.Fingerprints, "wrong")
	_, _, err = httpdtest.UpdateUser(sftpUser, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(sftpUser, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	out, err := runSSHCommand("md5sum", sftpUser, usePubKey)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "d41d8cd98f00b204e9800998ecf8427e")

	sftpUser.FsConfig.SFTPConfig.Fingerprints = []string{"wrong"}
	_, _, err = httpdtest.UpdateUser(sftpUser, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(sftpUser, usePubKey)
	if !assert.Error(t, err) {
		defer conn.Close()
		defer client.Close()
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestChtimes(t *testing.T) {
	usePubKey := false
	localUser, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(65535)
			testDir := "test" //nolint:goconst
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			acmodTime := time.Now()
			err = client.Chtimes(testFileName, acmodTime, acmodTime)
			assert.NoError(t, err)
			newFi, err := client.Lstat(testFileName)
			assert.NoError(t, err)
			diff := math.Abs(newFi.ModTime().Sub(acmodTime).Seconds())
			assert.LessOrEqual(t, diff, float64(1))
			err = client.Chtimes("invalidFile", acmodTime, acmodTime)
			assert.EqualError(t, err, os.ErrNotExist.Error())
			err = client.Mkdir(testDir)
			assert.NoError(t, err)
			err = client.Chtimes(testDir, acmodTime, acmodTime)
			assert.NoError(t, err)
			newFi, err = client.Lstat(testDir)
			assert.NoError(t, err)
			diff = math.Abs(newFi.ModTime().Sub(acmodTime).Seconds())
			assert.LessOrEqual(t, diff, float64(1))
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

// basic tests to verify virtual chroot, should be improved to cover more cases ...
func TestEscapeHomeDir(t *testing.T) {
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	dirOutsideHome := filepath.Join(homeBasePath, defaultUsername+"1", "dir")
	err = os.MkdirAll(dirOutsideHome, os.ModePerm)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		testDir := "testDir" //nolint:goconst
		linkPath := filepath.Join(homeBasePath, defaultUsername, testDir)
		err = os.Symlink(homeBasePath, linkPath)
		assert.NoError(t, err)
		_, err = client.ReadDir(testDir)
		assert.Error(t, err, "reading a symbolic link outside home dir should not succeeded")
		err = os.Remove(linkPath)
		assert.NoError(t, err)
		err = os.Symlink(dirOutsideHome, linkPath)
		assert.NoError(t, err)
		_, err := client.ReadDir(testDir)
		assert.Error(t, err, "reading a symbolic link outside home dir should not succeeded")
		err = client.Chmod(path.Join(testDir, "sub", "dir"), os.ModePerm)
		assert.ErrorIs(t, err, os.ErrPermission)
		assert.Error(t, err, "setstat on a file outside home dir must fail")
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		remoteDestPath := path.Join("..", "..", testFileName)
		err = sftpUploadFile(testFilePath, remoteDestPath, testFileSize, client)
		assert.NoError(t, err)
		_, err = client.Lstat(testFileName)
		assert.NoError(t, err)
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		linkPath = filepath.Join(homeBasePath, defaultUsername, testFileName)
		err = os.Symlink(homeBasePath, linkPath)
		assert.NoError(t, err)
		err = sftpDownloadFile(testFileName, testFilePath, 0, client)
		assert.Error(t, err, "download file outside home dir must fail")
		err = sftpUploadFile(testFilePath, remoteDestPath, testFileSize, client)
		assert.Error(t, err, "overwrite a file outside home dir must fail")
		err = client.Chmod(remoteDestPath, 0644)
		assert.Error(t, err, "setstat on a file outside home dir must fail")
		err = os.Remove(linkPath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(filepath.Join(homeBasePath, defaultUsername+"1"))
	assert.NoError(t, err)
}

func TestEscapeSFTPFsPrefix(t *testing.T) {
	usePubKey := false
	localUser, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	u := getTestSFTPUser(usePubKey)
	sftpPrefix := "/prefix"
	outPrefix1 := "/pre"
	outPrefix2 := sftpPrefix + "1"
	out1 := "out1"
	out2 := "out2"
	u.FsConfig.SFTPConfig.Prefix = sftpPrefix
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(localUser, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.Mkdir(sftpPrefix)
		assert.NoError(t, err)
		err = client.Mkdir(outPrefix1)
		assert.NoError(t, err)
		err = client.Mkdir(outPrefix2)
		assert.NoError(t, err)
		err = client.Symlink(outPrefix1, path.Join(sftpPrefix, out1))
		assert.NoError(t, err)
		err = client.Symlink(outPrefix2, path.Join(sftpPrefix, out2))
		assert.NoError(t, err)
	}

	conn, client, err = getSftpClient(sftpUser, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		contents, err := client.ReadDir("/")
		assert.NoError(t, err)
		assert.Len(t, contents, 2)
		_, err = client.ReadDir(out1)
		assert.Error(t, err)
		_, err = client.ReadDir(out2)
		assert.Error(t, err)
		err = client.Mkdir(path.Join(out1, "subout1"))
		assert.Error(t, err)
		err = client.Mkdir(path.Join(out2, "subout2"))
		assert.Error(t, err)
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestGetMimeTypeSFTPFs(t *testing.T) {
	usePubKey := false
	localUser, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(localUser, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		sftpFile, err := client.OpenFile(testFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
		if assert.NoError(t, err) {
			testData := []byte("some UTF-8 text so we should get a text/plain mime type")
			n, err := sftpFile.Write(testData)
			assert.NoError(t, err)
			assert.Equal(t, len(testData), n)
			err = sftpFile.Close()
			assert.NoError(t, err)
		}
	}

	sftpUser.FsConfig.SFTPConfig.Password = kms.NewPlainSecret(defaultPassword)
	sftpUser.FsConfig.SFTPConfig.PrivateKey = kms.NewEmptySecret()
	fs, err := sftpUser.GetFilesystem("connID")
	if assert.NoError(t, err) {
		assert.True(t, vfs.IsSFTPFs(fs))
		mime, err := fs.GetMimeType(testFileName)
		assert.NoError(t, err)
		assert.Equal(t, "text/plain; charset=utf-8", mime)
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestHomeSpecialChars(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.HomeDir = filepath.Join(homeBasePath, "abc açà#&%lk")
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		files, err := client.ReadDir(".")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(files))
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLogin(t *testing.T) {
	u := getTestUser(false)
	u.PublicKeys = []string{testPubKey}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, false)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, user.LastLogin, int64(0), "last login must be updated after a successful login: %v", user.LastLogin)
	}
	conn, client, err = getSftpClient(user, true)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Password = "invalid password"
	conn, client, err = getSftpClient(user, false)
	if !assert.Error(t, err, "login with invalid password must fail") {
		client.Close()
		conn.Close()
	}
	// testPubKey1 is not authorized
	user.PublicKeys = []string{testPubKey1}
	user.Password = ""
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, true)
	if !assert.Error(t, err, "login with invalid public key must fail") {
		defer conn.Close()
		defer client.Close()
	}
	// login a user with multiple public keys, only the second one is valid
	user.PublicKeys = []string{testPubKey1, testPubKey}
	user.Password = ""
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, true)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginUserCert(t *testing.T) {
	u := getTestUser(true)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	// try login using a cert signed from a trusted CA
	signer, err := getSignerForUserCert([]byte(testCertValid))
	assert.NoError(t, err)
	conn, client, err := getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	// revoke the certificate
	certs := []string{"SHA256:OkxVB1ImSJ2XeI8nA2Wg+6zJVlxdevD1FYBSEJjFEN4"}
	data, err := json.Marshal(certs)
	assert.NoError(t, err)
	err = os.WriteFile(revokeUserCerts, data, 0644)
	assert.NoError(t, err)
	err = sftpd.Reload()
	assert.NoError(t, err)
	conn, client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}
	// if we remove the revoked certificate login should work again
	certs = []string{"SHA256:bsBRHC/xgiqBJdSuvSTNpJNLTISP/G356jNMCRYC5Es, SHA256:1kxVB1ImSJ2XeI8nA2Wg+6zJVlxdevD1FYBSEJjFEN4"}
	data, err = json.Marshal(certs)
	assert.NoError(t, err)
	err = os.WriteFile(revokeUserCerts, data, 0644)
	assert.NoError(t, err)
	err = sftpd.Reload()
	assert.NoError(t, err)
	conn, client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	// try login using a cert signed from an untrusted CA
	signer, err = getSignerForUserCert([]byte(testCertUntrustedCA))
	assert.NoError(t, err)
	conn, client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}
	// try login using an host certificate instead of an user certificate
	signer, err = getSignerForUserCert([]byte(testHostCert))
	assert.NoError(t, err)
	conn, client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}
	// try login using a user certificate with an authorized source address different from localhost
	signer, err = getSignerForUserCert([]byte(testCertOtherSourceAddress))
	assert.NoError(t, err)
	conn, client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}
	// try login using an expired certificate
	signer, err = getSignerForUserCert([]byte(testCertExpired))
	assert.NoError(t, err)
	conn, client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}
	// try login using a certificate with no principals
	signer, err = getSignerForUserCert([]byte(testCertNoPrincipals))
	assert.NoError(t, err)
	conn, client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	// the user does not exist
	signer, err = getSignerForUserCert([]byte(testCertValid))
	assert.NoError(t, err)
	conn, client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}

	// now login with a username not in the set of valid principals for the given certificate
	u.Username += "1"
	user, _, err = httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	signer, err = getSignerForUserCert([]byte(testCertValid))
	assert.NoError(t, err)
	conn, client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}

	err = os.WriteFile(revokeUserCerts, []byte(`[]`), 0644)
	assert.NoError(t, err)
	err = sftpd.Reload()
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestMultiStepLoginKeyAndPwd(t *testing.T) {
	u := getTestUser(true)
	u.Password = defaultPassword
	u.Filters.DeniedLoginMethods = append(u.Filters.DeniedLoginMethods, []string{
		dataprovider.SSHLoginMethodKeyAndKeyboardInt,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}...)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, true)
	if !assert.Error(t, err, "login with public key is disallowed and must fail") {
		client.Close()
		conn.Close()
	}
	conn, client, err = getSftpClient(user, true)
	if !assert.Error(t, err, "login with password is disallowed and must fail") {
		client.Close()
		conn.Close()
	}
	signer, _ := ssh.ParsePrivateKey([]byte(testPrivateKey))
	authMethods := []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.Password(defaultPassword),
	}
	conn, client, err = getCustomAuthSftpClient(user, authMethods, "")
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	conn, client, err = getCustomAuthSftpClient(user, authMethods, sftpSrvAddr2222)
	if !assert.Error(t, err, "password auth is disabled on port 2222, multi-step auth must fail") {
		client.Close()
		conn.Close()
	}
	authMethods = []ssh.AuthMethod{
		ssh.Password(defaultPassword),
		ssh.PublicKeys(signer),
	}
	_, _, err = getCustomAuthSftpClient(user, authMethods, "")
	assert.Error(t, err, "multi step auth login with wrong order must fail")
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestMultiStepLoginKeyAndKeyInt(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser(true)
	u.Password = defaultPassword
	u.Filters.DeniedLoginMethods = append(u.Filters.DeniedLoginMethods, []string{
		dataprovider.SSHLoginMethodKeyAndPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}...)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, true)
	if !assert.Error(t, err, "login with public key is disallowed and must fail") {
		client.Close()
		conn.Close()
	}

	signer, _ := ssh.ParsePrivateKey([]byte(testPrivateKey))
	authMethods := []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			return []string{"1", "2"}, nil
		}),
	}
	conn, client, err = getCustomAuthSftpClient(user, authMethods, "")
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	conn, client, err = getCustomAuthSftpClient(user, authMethods, sftpSrvAddr2222)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	authMethods = []ssh.AuthMethod{
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			return []string{"1", "2"}, nil
		}),
		ssh.PublicKeys(signer),
	}
	_, _, err = getCustomAuthSftpClient(user, authMethods, "")
	assert.Error(t, err, "multi step auth login with wrong order must fail")

	authMethods = []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.Password(defaultPassword),
	}
	_, _, err = getCustomAuthSftpClient(user, authMethods, "")
	assert.Error(t, err, "multi step auth login with wrong method must fail")

	user.Filters.DeniedLoginMethods = nil
	user.Filters.DeniedLoginMethods = append(user.Filters.DeniedLoginMethods, []string{
		dataprovider.SSHLoginMethodKeyAndKeyboardInt,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}...)
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, _, err = getCustomAuthSftpClient(user, authMethods, sftpSrvAddr2222)
	assert.Error(t, err)
	conn, client, err = getCustomAuthSftpClient(user, authMethods, "")
	if assert.NoError(t, err) {
		assert.NoError(t, checkBasicSFTP(client))
		client.Close()
		conn.Close()
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestMultiStepLoginCertAndPwd(t *testing.T) {
	u := getTestUser(true)
	u.Password = defaultPassword
	u.Filters.DeniedLoginMethods = append(u.Filters.DeniedLoginMethods, []string{
		dataprovider.SSHLoginMethodKeyAndKeyboardInt,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}...)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	signer, err := getSignerForUserCert([]byte(testCertValid))
	assert.NoError(t, err)
	authMethods := []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.Password(defaultPassword),
	}
	conn, client, err := getCustomAuthSftpClient(user, authMethods, "")
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	signer, err = getSignerForUserCert([]byte(testCertOtherSourceAddress))
	assert.NoError(t, err)
	authMethods = []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.Password(defaultPassword),
	}
	conn, client, err = getCustomAuthSftpClient(user, authMethods, "")
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginUserStatus(t *testing.T) {
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, user.LastLogin, int64(0), "last login must be updated after a successful login: %v", user.LastLogin)
	}
	user.Status = 0
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login for a disabled user must fail") {
		client.Close()
		conn.Close()
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginUserExpiration(t *testing.T) {
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, user.LastLogin, int64(0), "last login must be updated after a successful login: %v", user.LastLogin)
	}
	user.ExpirationDate = util.GetTimeAsMsSinceEpoch(time.Now()) - 120000
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login for an expired user must fail") {
		client.Close()
		conn.Close()
	}
	user.ExpirationDate = util.GetTimeAsMsSinceEpoch(time.Now()) + 120000
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginWithDatabaseCredentials(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.FsConfig.Provider = sdk.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "testbucket"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret(`{ "type": "service_account" }`)

	providerConf := config.GetProviderConf()
	providerConf.PreferDatabaseCredentials = true
	credentialsFile := filepath.Join(providerConf.CredentialsPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
	if !filepath.IsAbs(credentialsFile) {
		credentialsFile = filepath.Join(configDir, credentialsFile)
	}

	assert.NoError(t, dataprovider.Close())

	err := dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	if _, err = os.Stat(credentialsFile); err == nil {
		// remove the credentials file
		assert.NoError(t, os.Remove(credentialsFile))
	}

	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.FsConfig.GCSConfig.Credentials.GetStatus())
	assert.NotEmpty(t, user.FsConfig.GCSConfig.Credentials.GetPayload())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetAdditionalData())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetKey())

	assert.NoFileExists(t, credentialsFile)

	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	assert.NoError(t, dataprovider.Close())
	assert.NoError(t, config.LoadConfig(configDir, ""))
	providerConf = config.GetProviderConf()
	assert.NoError(t, dataprovider.Initialize(providerConf, configDir, true))
}

func TestLoginInvalidFs(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.PreferDatabaseCredentials = false
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	usePubKey := true
	u := getTestUser(usePubKey)
	u.FsConfig.Provider = sdk.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("invalid JSON for credentials")
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	providerConf = config.GetProviderConf()
	credentialsFile := filepath.Join(providerConf.CredentialsPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
	if !filepath.IsAbs(credentialsFile) {
		credentialsFile = filepath.Join(configDir, credentialsFile)
	}

	// now remove the credentials file so the filesystem creation will fail
	err = os.Remove(credentialsFile)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login must fail, the user has an invalid filesystem config") {
		client.Close()
		conn.Close()
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
}

func TestDeniedProtocols(t *testing.T) {
	u := getTestUser(true)
	u.Filters.DeniedProtocols = []string{common.ProtocolSSH}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, true)
	if !assert.Error(t, err, "SSH protocol is disabled, authentication must fail") {
		client.Close()
		conn.Close()
	}
	user.Filters.DeniedProtocols = []string{common.ProtocolFTP, common.ProtocolWebDAV}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, true)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDeniedLoginMethods(t *testing.T) {
	u := getTestUser(true)
	u.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPublicKey, dataprovider.LoginMethodPassword}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, true)
	if !assert.Error(t, err, "public key login is disabled, authentication must fail") {
		client.Close()
		conn.Close()
	}
	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodKeyboardInteractive, dataprovider.LoginMethodPassword}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, true)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Password = defaultPassword
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	conn, client, err = getSftpClient(user, false)
	if !assert.Error(t, err, "password login is disabled, authentication must fail") {
		client.Close()
		conn.Close()
	}
	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodKeyboardInteractive, dataprovider.SSHLoginMethodPublicKey}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, false)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginWithIPFilters(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Filters.DeniedIP = []string{"192.167.0.0/24", "172.18.0.0/16"}
	u.Filters.AllowedIP = []string{}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, user.LastLogin, int64(0), "last login must be updated after a successful login: %v", user.LastLogin)
	}
	user.Filters.AllowedIP = []string{"127.0.0.0/8"}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Filters.AllowedIP = []string{"172.19.0.0/16"}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login from an not allowed IP must fail") {
		client.Close()
		conn.Close()
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginAfterUserUpdateEmptyPwd(t *testing.T) {
	usePubKey := false
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	user.Password = ""
	user.PublicKeys = []string{}
	// password and public key should remain unchanged
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginAfterUserUpdateEmptyPubKey(t *testing.T) {
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	user.Password = ""
	user.PublicKeys = []string{}
	// password and public key should remain unchanged
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginKeyboardInteractiveAuth(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	user, _, err := httpdtest.AddUser(getTestUser(false), http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err := getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Status = 0
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the user is disabled") {
		client.Close()
		conn.Close()
	}
	user.Status = 1
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, -1), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the script returned -1") {
		client.Close()
		conn.Close()
	}
	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, true, 1), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the script returned bad json") {
		client.Close()
		conn.Close()
	}
	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 5, true, 1), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the script returned bad json") {
		client.Close()
		conn.Close()
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestInteractiveLoginWithPasscode(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	user, _, err := httpdtest.AddUser(getTestUser(false), http.StatusCreated)
	assert.NoError(t, err)
	// test password check
	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptForBuiltinChecks(false, 1), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err := getKeyboardInteractiveSftpClient(user, []string{defaultPassword})
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	// wrong password
	_, _, err = getKeyboardInteractiveSftpClient(user, []string{"wrong_password"})
	assert.Error(t, err)
	// correct password but the script returns an error
	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptForBuiltinChecks(false, 0), os.ModePerm)
	assert.NoError(t, err)
	_, _, err = getKeyboardInteractiveSftpClient(user, []string{"wrong_password"})
	assert.Error(t, err)
	// add multi-factor authentication
	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolSSH},
	}
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)

	passcode, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	assert.NoError(t, err)
	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptForBuiltinChecks(true, 1), os.ModePerm)
	assert.NoError(t, err)

	passwordAsked := false
	passcodeAsked := false
	authMethods := []ssh.AuthMethod{
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			var answers []string
			if strings.HasPrefix(questions[0], "Password") {
				answers = append(answers, defaultPassword)
				passwordAsked = true
			} else {
				answers = append(answers, passcode)
				passcodeAsked = true
			}
			return answers, nil
		}),
	}
	conn, client, err = getCustomAuthSftpClient(user, authMethods, "")
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	assert.True(t, passwordAsked)
	assert.True(t, passcodeAsked)
	// the same passcode cannot be reused
	_, _, err = getCustomAuthSftpClient(user, authMethods, "")
	assert.Error(t, err)
	// correct passcode but the script returns an error
	configName, _, secret, _, err = mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolSSH},
	}
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	passcode, err = totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	assert.NoError(t, err)
	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptForBuiltinChecks(true, 0), os.ModePerm)
	assert.NoError(t, err)
	passwordAsked = false
	passcodeAsked = false
	_, _, err = getCustomAuthSftpClient(user, authMethods, "")
	assert.Error(t, err)
	authMethods = []ssh.AuthMethod{
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			var answers []string
			if strings.HasPrefix(questions[0], "Password") {
				answers = append(answers, defaultPassword)
				passwordAsked = true
			} else {
				answers = append(answers, passcode)
				passcodeAsked = true
			}
			return answers, nil
		}),
	}
	_, _, err = getCustomAuthSftpClient(user, authMethods, "")
	assert.Error(t, err)
	assert.True(t, passwordAsked)
	assert.True(t, passcodeAsked)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSecondFactorRequirement(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Filters.TwoFactorAuthProtocols = []string{common.ProtocolSSH}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	_, _, err = getSftpClient(user, usePubKey)
	assert.Error(t, err)

	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolSSH},
	}
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)

	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestNamingRules(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.NamingRules = 7
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Username = "useR@user.com "
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	assert.Equal(t, "user@user.com", user.Username)
	conn, client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	u.Password = defaultPassword
	_, _, err = httpdtest.UpdateUser(u, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(u, false)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpdtest.RemoveUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(u.GetHomeDir())
	assert.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
}

func TestPreLoginScript(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
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

	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(user, true), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "pre-login script returned a non json response, login must fail") {
		client.Close()
		conn.Close()
	}
	// now disable the the hook
	user.Filters.Hooks.PreLoginDisabled = true
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	user.Filters.Hooks.PreLoginDisabled = false
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	user.Status = 0
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(user, false), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "pre-login script returned a disabled user, login must fail") {
		client.Close()
		conn.Close()
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

func TestPreLoginUserCreation(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := false
	u := getTestUser(usePubKey)
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

	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusNotFound)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
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

func TestPreLoginHookPreserveMFAConfig(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := false
	u := getTestUser(usePubKey)
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

	conn, client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	// add multi-factor authentication
	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, user.Filters.RecoveryCodes, 0)
	assert.False(t, user.Filters.TOTPConfig.Enabled)
	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolSSH},
	}
	for i := 0; i < 12; i++ {
		user.Filters.RecoveryCodes = append(user.Filters.RecoveryCodes, dataprovider.RecoveryCode{
			Secret: kms.NewPlainSecret(fmt.Sprintf("RC-%v", strings.ToUpper(util.GenerateUniqueID()))),
		})
	}
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)

	conn, client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, user.Filters.RecoveryCodes, 12)
	assert.True(t, user.Filters.TOTPConfig.Enabled)
	assert.Equal(t, configName, user.Filters.TOTPConfig.ConfigName)
	assert.Equal(t, []string{common.ProtocolSSH}, user.Filters.TOTPConfig.Protocols)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.Filters.TOTPConfig.Secret.GetStatus())

	err = os.WriteFile(extAuthPath, getExitCodeScriptContent(0), os.ModePerm)
	assert.NoError(t, err)

	conn, client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, user.Filters.RecoveryCodes, 12)
	assert.True(t, user.Filters.TOTPConfig.Enabled)
	assert.Equal(t, configName, user.Filters.TOTPConfig.ConfigName)
	assert.Equal(t, []string{common.ProtocolSSH}, user.Filters.TOTPConfig.Protocols)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.Filters.TOTPConfig.Secret.GetStatus())

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

	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(preDownloadPath, getExitCodeScriptContent(0), os.ModePerm)
	assert.NoError(t, err)
	testFileSize := int64(131072)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
	}

	remoteSCPDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	err = scpDownload(localDownloadPath, remoteSCPDownPath, false, false)
	assert.NoError(t, err)

	err = os.WriteFile(preDownloadPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)

	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.ErrorIs(t, err, os.ErrPermission)
	}

	err = scpDownload(localDownloadPath, remoteSCPDownPath, false, false)
	assert.Error(t, err)

	common.Config.Actions.Hook = "http://127.0.0.1:8080/web/admin/login"

	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
	}
	err = scpDownload(localDownloadPath, remoteSCPDownPath, false, false)
	assert.NoError(t, err)

	common.Config.Actions.Hook = "http://127.0.0.1:8080/"

	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.ErrorIs(t, err, os.ErrPermission)
	}
	err = scpDownload(localDownloadPath, remoteSCPDownPath, false, false)
	assert.Error(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
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

	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(preUploadPath, getExitCodeScriptContent(0), os.ModePerm)
	assert.NoError(t, err)
	testFileSize := int64(131072)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
	}

	remoteSCPUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	err = scpUpload(testFilePath, remoteSCPUpPath, true, false)
	assert.NoError(t, err)

	err = os.WriteFile(preUploadPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)

	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = sftpUploadFile(testFilePath, testFileName+"1", testFileSize, client)
		assert.ErrorIs(t, err, os.ErrPermission)
	}
	err = scpUpload(testFilePath, remoteSCPUpPath, true, false)
	assert.Error(t, err)

	common.Config.Actions.Hook = "http://127.0.0.1:8080/web/client/login"

	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
	}
	err = scpUpload(testFilePath, remoteSCPUpPath, true, false)
	assert.NoError(t, err)

	common.Config.Actions.Hook = "http://127.0.0.1:8080/web"

	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = sftpUploadFile(testFilePath, testFileName+"1", testFileSize, client)
		assert.ErrorIs(t, err, os.ErrPermission)
	}

	err = scpUpload(testFilePath, remoteSCPUpPath, true, false)
	assert.Error(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.Actions.ExecuteOn = oldExecuteOn
	common.Config.Actions.Hook = oldHook
}

func TestPostConnectHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	common.Config.PostConnectHook = postConnectPath

	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.WriteFile(postConnectPath, getExitCodeScriptContent(0), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}
	err = os.WriteFile(postConnectPath, getExitCodeScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}

	common.Config.PostConnectHook = "http://127.0.0.1:8080/healthz"

	conn, client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	common.Config.PostConnectHook = "http://127.0.0.1:8080/notfound"
	conn, client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.PostConnectHook = ""
}

func TestCheckPwdHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(checkPwdPath, getCheckPwdScriptsContents(2, defaultPassword), os.ModePerm)
	assert.NoError(t, err)
	providerConf.CheckPasswordHook = checkPwdPath
	providerConf.CheckPasswordScope = 1
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		client.Close()
		conn.Close()
	}

	err = os.WriteFile(checkPwdPath, getCheckPwdScriptsContents(0, defaultPassword), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}

	// now disable the the hook
	user.Filters.Hooks.CheckPasswordDisabled = true
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		client.Close()
		conn.Close()
	}

	// enable the hook again
	user.Filters.Hooks.CheckPasswordDisabled = false
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	err = os.WriteFile(checkPwdPath, getCheckPwdScriptsContents(1, ""), os.ModePerm)
	assert.NoError(t, err)
	user.Password = defaultPassword + "1"
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		client.Close()
		conn.Close()
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	providerConf.CheckPasswordScope = 6
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	user, _, err = httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	user.Password = defaultPassword + "1"
	conn, client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
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
	err = os.Remove(checkPwdPath)
	assert.NoError(t, err)
}

func TestLoginExternalAuthPwdAndPubKey(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	testFileSize := int64(65535)
	conn, client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	u.Username = defaultUsername + "1"
	conn, client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "external auth login with invalid user must fail") {
		client.Close()
		conn.Close()
	}
	usePubKey = false
	u = getTestUser(usePubKey)
	u.PublicKeys = []string{}
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, false, ""), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(user.PublicKeys))
	assert.Equal(t, testFileSize, user.UsedQuotaSize)
	assert.Equal(t, 1, user.UsedQuotaFiles)

	u.Status = 0
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, false, ""), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err) {
		client.Close()
		conn.Close()
	}
	// now disable the the hook
	user.Filters.Hooks.ExternalAuthDisabled = true
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
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
	err = os.Remove(extAuthPath)
	assert.NoError(t, err)
}

func TestExternalAuthMultiStepLoginKeyAndPwd(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser(true)
	u.Password = defaultPassword
	u.Filters.DeniedLoginMethods = append(u.Filters.DeniedLoginMethods, []string{
		dataprovider.SSHLoginMethodKeyAndKeyboardInt,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}...)

	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	signer, err := ssh.ParsePrivateKey([]byte(testPrivateKey))
	assert.NoError(t, err)
	authMethods := []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.Password(defaultPassword),
	}
	conn, client, err := getCustomAuthSftpClient(u, authMethods, "")
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	// wrong sequence should fail
	authMethods = []ssh.AuthMethod{
		ssh.Password(defaultPassword),
		ssh.PublicKeys(signer),
	}
	_, _, err = getCustomAuthSftpClient(u, authMethods, "")
	assert.Error(t, err)

	// public key only auth must fail
	_, _, err = getSftpClient(u, true)
	assert.Error(t, err)
	// password only auth must fail
	_, _, err = getSftpClient(u, false)
	assert.Error(t, err)

	_, err = httpdtest.RemoveUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(u.GetHomeDir())
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

func TestExternalAuthEmptyResponse(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	testFileSize := int64(65535)
	// the user will be created
	conn, client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}

	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(user.PublicKeys))
	assert.Equal(t, testFileSize, user.UsedQuotaSize)
	assert.Equal(t, 1, user.UsedQuotaFiles)
	// now modify the user
	user.MaxSessions = 10
	user.QuotaFiles = 100
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, true, ""), os.ModePerm)
	assert.NoError(t, err)

	conn, client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 10, user.MaxSessions)
	assert.Equal(t, 100, user.QuotaFiles)

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

func TestExternalAuthDifferentUsername(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := false
	extAuthUsername := "common_user"
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, false, extAuthUsername), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	// the user logins using "defaultUsername" and the external auth returns "extAuthUsername"
	testFileSize := int64(65535)
	conn, client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}

	// logins again to test that used quota is preserved
	conn, client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	_, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusNotFound)
	assert.NoError(t, err)

	user, _, err := httpdtest.GetUserByUsername(extAuthUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(user.PublicKeys))
	assert.Equal(t, testFileSize, user.UsedQuotaSize)
	assert.Equal(t, 1, user.UsedQuotaFiles)

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

func TestLoginExternalAuth(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	mappedPath := filepath.Join(os.TempDir(), "vdir1")
	folderName := filepath.Base(mappedPath)
	extAuthScopes := []int{1, 2}
	for _, authScope := range extAuthScopes {
		var usePubKey bool
		if authScope == 1 {
			usePubKey = false
		} else {
			usePubKey = true
		}
		u := getTestUser(usePubKey)
		u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name:       folderName,
				MappedPath: mappedPath,
			},
			VirtualPath: "/vpath",
			QuotaFiles:  1 + authScope,
			QuotaSize:   10 + int64(authScope),
		})
		err := dataprovider.Close()
		assert.NoError(t, err)
		err = config.LoadConfig(configDir, "")
		assert.NoError(t, err)
		providerConf := config.GetProviderConf()
		err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, false, ""), os.ModePerm)
		assert.NoError(t, err)
		providerConf.ExternalAuthHook = extAuthPath
		providerConf.ExternalAuthScope = authScope
		err = dataprovider.Initialize(providerConf, configDir, true)
		assert.NoError(t, err)

		conn, client, err := getSftpClient(u, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			assert.NoError(t, checkBasicSFTP(client))
		}
		if !usePubKey {
			found, match := dataprovider.CheckCachedPassword(defaultUsername, defaultPassword)
			assert.True(t, found)
			assert.True(t, match)
		}
		u.Username = defaultUsername + "1"
		conn, client, err = getSftpClient(u, usePubKey)
		if !assert.Error(t, err, "external auth login with invalid user must fail") {
			client.Close()
			conn.Close()
		}
		usePubKey = !usePubKey
		u = getTestUser(usePubKey)
		conn, client, err = getSftpClient(u, usePubKey)
		if !assert.Error(t, err, "external auth login with valid user but invalid auth scope must fail") {
			client.Close()
			conn.Close()
		}
		user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, user.VirtualFolders, 1) {
			folder := user.VirtualFolders[0]
			assert.Equal(t, folderName, folder.Name)
			assert.Equal(t, mappedPath, folder.MappedPath)
			assert.Equal(t, 1+authScope, folder.QuotaFiles)
			assert.Equal(t, 10+int64(authScope), folder.QuotaSize)
		}
		_, err = httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)

		_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
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
}

func TestLoginExternalAuthCache(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	u := getTestUser(false)
	u.Filters.ExternalAuthCacheTime = 120
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 1
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(u, false)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	lastLogin := user.LastLogin
	assert.Greater(t, lastLogin, int64(0))
	assert.Equal(t, u.Filters.ExternalAuthCacheTime, user.Filters.ExternalAuthCacheTime)
	// the auth should be now cached so update the hook to return an error
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, true, false, ""), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(u, false)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, lastLogin, user.LastLogin)

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

func TestLoginExternalAuthInteractive(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := false
	u := getTestUser(usePubKey)
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 4
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	err = os.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), os.ModePerm)
	assert.NoError(t, err)
	conn, client, err := getKeyboardInteractiveSftpClient(u, []string{"1", "2"})
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	u.Username = defaultUsername + "1"
	conn, client, err = getKeyboardInteractiveSftpClient(u, []string{"1", "2"})
	if !assert.Error(t, err, "external auth login with invalid user must fail") {
		client.Close()
		conn.Close()
	}
	usePubKey = true
	u = getTestUser(usePubKey)
	conn, client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "external auth login with valid user but invalid auth scope must fail") {
		client.Close()
		conn.Close()
	}
	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
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

func TestLoginExternalAuthErrors(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, true, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "login must fail, external auth returns a non json response") {
		client.Close()
		conn.Close()
	}

	usePubKey = false
	u = getTestUser(usePubKey)
	conn, client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "login must fail, external auth returns a non json response") {
		client.Close()
		conn.Close()
	}
	_, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusNotFound)
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

func TestExternalAuthPreserveMFAConfig(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := false
	u := getTestUser(usePubKey)
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	// add multi-factor authentication
	user, _, err := httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, user.Filters.RecoveryCodes, 0)
	assert.False(t, user.Filters.TOTPConfig.Enabled)
	configName, _, secret, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	assert.NoError(t, err)
	user.Password = defaultPassword
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(secret),
		Protocols:  []string{common.ProtocolSSH},
	}
	for i := 0; i < 12; i++ {
		user.Filters.RecoveryCodes = append(user.Filters.RecoveryCodes, dataprovider.RecoveryCode{
			Secret: kms.NewPlainSecret(fmt.Sprintf("RC-%v", strings.ToUpper(util.GenerateUniqueID()))),
		})
	}
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	// login again and check that the MFA configs are preserved
	conn, client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, user.Filters.RecoveryCodes, 12)
	assert.True(t, user.Filters.TOTPConfig.Enabled)
	assert.Equal(t, configName, user.Filters.TOTPConfig.ConfigName)
	assert.Equal(t, []string{common.ProtocolSSH}, user.Filters.TOTPConfig.Protocols)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.Filters.TOTPConfig.Secret.GetStatus())

	err = os.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, true, ""), os.ModePerm)
	assert.NoError(t, err)

	conn, client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	user, _, err = httpdtest.GetUserByUsername(defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Len(t, user.Filters.RecoveryCodes, 12)
	assert.True(t, user.Filters.TOTPConfig.Enabled)
	assert.Equal(t, configName, user.Filters.TOTPConfig.ConfigName)
	assert.Equal(t, []string{common.ProtocolSSH}, user.Filters.TOTPConfig.Protocols)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, user.Filters.TOTPConfig.Secret.GetStatus())

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

func TestQuotaDisabledError(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.TrackQuota = 0
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName+"1", testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName+"1", testFileName+".rename")
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
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
}

//nolint:dupl
func TestMaxConnections(t *testing.T) {
	oldValue := common.Config.MaxTotalConnections
	common.Config.MaxTotalConnections = 1

	assert.Eventually(t, func() bool {
		return common.Connections.GetClientConnections() == 0
	}, 1000*time.Millisecond, 50*time.Millisecond)

	usePubKey := true
	user := getTestUser(usePubKey)
	err := dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)
	user.Password = ""
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		assert.NoError(t, checkBasicSFTP(client))
		s, c, err := getSftpClient(user, usePubKey)
		if !assert.Error(t, err, "max total connections exceeded, new login should not succeed") {
			c.Close()
			s.Close()
		}
		err = client.Close()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}
	err = dataprovider.DeleteUser(user.Username, "", "")
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

	usePubKey := true
	user := getTestUser(usePubKey)
	err := dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)
	user.Password = ""
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		assert.NoError(t, checkBasicSFTP(client))
		s, c, err := getSftpClient(user, usePubKey)
		if !assert.Error(t, err, "max per host connections exceeded, new login should not succeed") {
			c.Close()
			s.Close()
		}
		err = client.Close()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}
	err = dataprovider.DeleteUser(user.Username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	common.Config.MaxPerHostConnections = oldValue
}

func TestMaxSessions(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Username += "1"
	u.MaxSessions = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		s, c, err := getSftpClient(user, usePubKey)
		if !assert.Error(t, err, "max sessions exceeded, new login should not succeed") {
			c.Close()
			s.Close()
		}
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSupportedExtensions(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		v, ok := client.HasExtension("statvfs@openssh.com")
		assert.Equal(t, "2", v)
		assert.True(t, ok)
		_, ok = client.HasExtension("hardlink@openssh.com")
		assert.False(t, ok)
		_, ok = client.HasExtension("posix-rename@openssh.com")
		assert.False(t, ok)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaFileReplace(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	u.QuotaFiles = 1000
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFileSize := int64(65535)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) { //nolint:dupl
			defer conn.Close()
			defer client.Close()
			expectedQuotaSize := testFileSize
			expectedQuotaFiles := 1
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			// now replace the same file, the quota must not change
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
			assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
			// now create a symlink, replace it with a file and check the quota
			// replacing a symlink is like uploading a new file
			err = client.Symlink(testFileName, testFileName+".link")
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
			assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
			expectedQuotaFiles++
			expectedQuotaSize += testFileSize
			err = sftpUploadFile(testFilePath, testFileName+".link", testFileSize, client)
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
			assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		}
		// now set a quota size restriction and upload the same file, upload should fail for space limit exceeded
		user.QuotaSize = testFileSize*2 - 1
		user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		conn, client, err = getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.Error(t, err, "quota size exceeded, file upload must fail")
			err = client.Remove(testFileName)
			assert.NoError(t, err)
		}
		if user.Username == defaultUsername {
			err = os.RemoveAll(user.GetHomeDir())
			assert.NoError(t, err)
			_, err = httpdtest.RemoveUser(user, http.StatusOK)
			assert.NoError(t, err)
			user.Password = defaultPassword
			user.ID = 0
			user.CreatedAt = 0
			user.QuotaSize = 0
			_, resp, err := httpdtest.AddUser(user, http.StatusCreated)
			assert.NoError(t, err, string(resp))
		}
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaRename(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	u.QuotaFiles = 1000
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFileSize := int64(65535)
	testFileSize1 := int64(65537)
	testFileName1 := "test_file1.dat" //nolint:goconst
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFilePath1 := filepath.Join(homeBasePath, testFileName1)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = createTestFile(testFilePath1, testFileSize1)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			err = client.Rename(testFileName, testFileName+".rename")
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath1, testFileName1, testFileSize1, client)
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 2, user.UsedQuotaFiles)
			assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
			err = client.Rename(testFileName1, testFileName+".rename")
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 1, user.UsedQuotaFiles)
			assert.Equal(t, testFileSize1, user.UsedQuotaSize)
			err = client.Symlink(testFileName+".rename", testFileName+".symlink")
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			// overwrite a symlink
			err = client.Rename(testFileName, testFileName+".symlink")
			assert.NoError(t, err)
			err = client.Mkdir("testdir")
			assert.NoError(t, err)
			err = client.Rename("testdir", "testdir1")
			assert.NoError(t, err)
			err = client.Mkdir("testdir")
			assert.NoError(t, err)
			err = client.Rename("testdir", "testdir1")
			assert.Error(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 2, user.UsedQuotaFiles)
			assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
			testDir := "tdir"
			err = client.Mkdir(testDir)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, path.Join(testDir, testFileName), testFileSize, client)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath1, path.Join(testDir, testFileName1), testFileSize1, client)
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 4, user.UsedQuotaFiles)
			assert.Equal(t, testFileSize*2+testFileSize1*2, user.UsedQuotaSize)
			err = client.Rename(testDir, testDir+"1")
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 4, user.UsedQuotaFiles)
			assert.Equal(t, testFileSize*2+testFileSize1*2, user.UsedQuotaSize)
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
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaScan(t *testing.T) {
	usePubKey := false
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	testFileSize := int64(65535)
	expectedQuotaSize := user.UsedQuotaSize + testFileSize
	expectedQuotaFiles := user.UsedQuotaFiles + 1
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	// create user with the same home dir, so there is at least an untracked file
	user, _, err = httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	_, err = httpdtest.StartQuotaScan(user, http.StatusAccepted)
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		scans, _, err := httpdtest.GetQuotaScans(http.StatusOK)
		if err == nil {
			return len(scans) == 0
		}
		return false
	}, 1*time.Second, 50*time.Millisecond)
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestMultipleQuotaScans(t *testing.T) {
	res := common.QuotaScans.AddUserQuotaScan(defaultUsername)
	assert.True(t, res)
	res = common.QuotaScans.AddUserQuotaScan(defaultUsername)
	assert.False(t, res, "add quota must fail if another scan is already active")
	assert.True(t, common.QuotaScans.RemoveUserQuotaScan(defaultUsername))
	activeScans := common.QuotaScans.GetUsersQuotaScans()
	assert.Equal(t, 0, len(activeScans))
	assert.False(t, common.QuotaScans.RemoveUserQuotaScan(defaultUsername))
}

func TestQuotaLimits(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	u.QuotaFiles = 1
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
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
	testFileName2 := "test_file2.dat" //nolint:goconst
	testFilePath2 := filepath.Join(homeBasePath, testFileName2)
	err = createTestFile(testFilePath2, testFileSize2)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		// test quota files
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			err = sftpUploadFile(testFilePath, testFileName+".quota", testFileSize, client)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName+".quota.1", testFileSize, client)
			if assert.Error(t, err, "user is over quota files, upload must fail") {
				assert.Contains(t, err.Error(), "SSH_FX_FAILURE")
				assert.Contains(t, err.Error(), common.ErrQuotaExceeded.Error())
			}
			// rename should work
			err = client.Rename(testFileName+".quota", testFileName)
			assert.NoError(t, err)
		}
		// test quota size
		user.QuotaSize = testFileSize - 1
		user.QuotaFiles = 0
		user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		conn, client, err = getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			err = sftpUploadFile(testFilePath, testFileName+".quota.1", testFileSize, client)
			if assert.Error(t, err, "user is over quota size, upload must fail") {
				assert.Contains(t, err.Error(), "SSH_FX_FAILURE")
				assert.Contains(t, err.Error(), common.ErrQuotaExceeded.Error())
			}
			err = client.Rename(testFileName, testFileName+".quota")
			assert.NoError(t, err)
			err = client.Rename(testFileName+".quota", testFileName)
			assert.NoError(t, err)
		}
		// now test quota limits while uploading the current file, we have 1 bytes remaining
		user.QuotaSize = testFileSize + 1
		user.QuotaFiles = 0
		user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		conn, client, err = getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			err = sftpUploadFile(testFilePath1, testFileName1, testFileSize1, client)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "SSH_FX_FAILURE")
				assert.Contains(t, err.Error(), common.ErrQuotaExceeded.Error())
			}
			_, err = client.Stat(testFileName1)
			assert.Error(t, err)
			_, err = client.Lstat(testFileName1)
			assert.Error(t, err)
			// overwriting an existing file will work if the resulting size is lesser or equal than the current one
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath2, testFileName, testFileSize2, client)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath1, testFileName, testFileSize1, client)
			assert.Error(t, err)
			_, err := client.Stat(testFileName)
			assert.Error(t, err)
		}
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
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
	err = os.Remove(testFilePath2)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestTransferQuotaLimits(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.DownloadDataTransfer = 1
	u.UploadDataTransfer = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(550000)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		// error while download is active
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), common.ErrReadQuotaExceeded.Error())
		}
		// error before starting the download
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), common.ErrReadQuotaExceeded.Error())
		}
		// error while upload is active
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), common.ErrQuotaExceeded.Error())
		}
		// error before starting the upload
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), common.ErrQuotaExceeded.Error())
		}
	}

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Greater(t, user.UsedDownloadDataTransfer, int64(1024*1024))
	assert.Greater(t, user.UsedUploadDataTransfer, int64(1024*1024))

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadMaxSize(t *testing.T) {
	testFileSize := int64(65535)
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Filters.MaxUploadFileSize = testFileSize + 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	testFileSize1 := int64(131072)
	testFileName1 := "test_file1.dat"
	testFilePath1 := filepath.Join(homeBasePath, testFileName1)
	err = createTestFile(testFilePath1, testFileSize1)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = sftpUploadFile(testFilePath1, testFileName1, testFileSize1, client)
		assert.Error(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		// now test overwrite an existing file with a size bigger than the allowed one
		err = createTestFile(filepath.Join(user.GetHomeDir(), testFileName1), testFileSize1)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, testFileName1, testFileSize1, client)
		assert.Error(t, err)
	}
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestBandwidthAndConnections(t *testing.T) {
	usePubKey := false
	testFileSize := int64(524288)
	u := getTestUser(usePubKey)
	u.UploadBandwidth = 120
	u.DownloadBandwidth = 100
	wantedUploadElapsed := 1000 * (testFileSize / 1024) / u.UploadBandwidth
	wantedDownloadElapsed := 1000 * (testFileSize / 1024) / u.DownloadBandwidth
	// 100 ms tolerance
	wantedUploadElapsed -= 100
	wantedDownloadElapsed -= 100
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		startTime := time.Now()
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		elapsed := time.Since(startTime).Nanoseconds() / 1000000
		assert.GreaterOrEqual(t, elapsed, wantedUploadElapsed, "upload bandwidth throttling not respected")
		startTime = time.Now()
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		c := sftpDownloadNonBlocking(testFileName, localDownloadPath, testFileSize, client)
		waitForActiveTransfers(t)
		// wait some additional arbitrary time to wait for transfer activity to happen
		// it is need to reach all the code in CheckIdleConnections
		time.Sleep(100 * time.Millisecond)
		err = <-c
		assert.NoError(t, err)
		elapsed = time.Since(startTime).Nanoseconds() / 1000000
		assert.GreaterOrEqual(t, elapsed, wantedDownloadElapsed, "download bandwidth throttling not respected")
		// test disconnection
		c = sftpUploadNonBlocking(testFilePath, testFileName+"_partial", testFileSize, client)
		waitForActiveTransfers(t)
		time.Sleep(100 * time.Millisecond)

		for _, stat := range common.Connections.GetStats() {
			common.Connections.Close(stat.ConnectionID)
		}
		err = <-c
		assert.Error(t, err, "connection closed while uploading: the upload must fail")
		assert.Eventually(t, func() bool {
			return len(common.Connections.GetStats()) == 0
		}, 10*time.Second, 200*time.Millisecond)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPatternsFilters(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFileSize := int64(131072)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName+".zip", testFileSize, client)
		assert.NoError(t, err)
	}
	user.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/",
			AllowedPatterns: []string{"*.zIp"},
			DeniedPatterns:  []string{},
		},
	}
	user.Filters.DisableFsChecks = true
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.Error(t, err)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.Error(t, err)
		err = client.Rename(testFileName, testFileName+"1")
		assert.Error(t, err)
		err = client.Remove(testFileName)
		assert.Error(t, err)
		err = sftpDownloadFile(testFileName+".zip", localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		err = client.Mkdir("dir.zip")
		assert.NoError(t, err)
		err = client.Rename("dir.zip", "dir1.zip")
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestVirtualFolders(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	folderName := filepath.Base(mappedPath)
	vdirPath := "/vdir/subdir"
	testDir := "/userDir"
	testDir1 := "/userDir1"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
	})
	u.Permissions[testDir] = []string{dataprovider.PermCreateDirs}
	u.Permissions[testDir1] = []string{dataprovider.PermCreateDirs, dataprovider.PermUpload, dataprovider.PermRename}
	u.Permissions[path.Join(testDir1, "subdir")] = []string{dataprovider.PermRename}

	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		// check virtual folder auto creation
		_, err = os.Stat(mappedPath)
		assert.NoError(t, err)
		testFileSize := int64(131072)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpDownloadFile(path.Join(vdirPath, testFileName), localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(vdirPath, "new_name")
		assert.Error(t, err, "renaming a virtual folder must fail")
		err = client.RemoveDirectory(vdirPath)
		assert.Error(t, err, "removing a virtual folder must fail")
		err = client.Mkdir(vdirPath)
		assert.Error(t, err, "creating a virtual folder must fail")
		err = client.Symlink(path.Join(vdirPath, testFileName), vdirPath)
		assert.Error(t, err, "symlink to a virtual folder must fail")
		err = client.Rename("/vdir", "/vdir1")
		assert.Error(t, err, "renaming a directory with a virtual folder inside must fail")
		err = client.RemoveDirectory("/vdir")
		assert.Error(t, err, "removing a directory with a virtual folder inside must fail")
		err = client.Mkdir("vdir1")
		assert.NoError(t, err)
		// rename empty dir /vdir1, we have permission on /
		err = client.Rename("vdir1", "vdir2")
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join("vdir2", testFileName), testFileSize, client)
		assert.NoError(t, err)
		// we don't have upload permission on testDir, we can only create dirs
		err = client.Rename("vdir2", testDir)
		assert.Error(t, err)
		// on testDir1 only symlink aren't allowed
		err = client.Rename("vdir2", testDir1)
		assert.NoError(t, err)
		err = client.Rename(testDir1, "vdir2")
		assert.NoError(t, err)
		err = client.MkdirAll(path.Join("vdir2", "subdir"))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join("vdir2", "subdir", testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename("vdir2", testDir1)
		assert.NoError(t, err)
		err = client.Rename(testDir1, "vdir2")
		assert.NoError(t, err)
		err = client.MkdirAll(path.Join("vdir2", "subdir", "subdir"))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join("vdir2", "subdir", "subdir", testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename("vdir2", testDir1)
		assert.NoError(t, err)
		err = client.Rename(testDir1, "vdir3")
		assert.NoError(t, err)
		err = client.Remove(path.Join("vdir3", "subdir", "subdir", testFileName))
		assert.NoError(t, err)
		err = client.RemoveDirectory(path.Join("vdir3", "subdir", "subdir"))
		assert.NoError(t, err)
		err = client.Rename("vdir3", testDir1)
		assert.NoError(t, err)
		err = client.Rename(testDir1, "vdir2")
		assert.NoError(t, err)
		err = client.Symlink(path.Join("vdir2", "subdir", testFileName), path.Join("vdir2", "subdir", "alink"))
		assert.NoError(t, err)
		err = client.Rename("vdir2", testDir1)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
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

func TestVirtualFoldersQuotaLimit(t *testing.T) {
	usePubKey := false
	u1 := getTestUser(usePubKey)
	u1.QuotaFiles = 1
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1" //nolint:goconst
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2" //nolint:goconst
	u1.VirtualFolders = append(u1.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u1.VirtualFolders = append(u1.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  1,
		QuotaSize:   0,
	})
	testFileSize := int64(131072)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err := createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	u2 := getTestUser(usePubKey)
	u2.QuotaSize = testFileSize + 1
	u2.VirtualFolders = append(u2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u2.VirtualFolders = append(u2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  0,
		QuotaSize:   testFileSize + 1,
	})
	users := []dataprovider.User{u1, u2}
	for _, u := range users {
		err = os.MkdirAll(mappedPath1, os.ModePerm)
		assert.NoError(t, err)
		err = os.MkdirAll(mappedPath2, os.ModePerm)
		assert.NoError(t, err)
		user, _, err := httpdtest.AddUser(u, http.StatusCreated)
		assert.NoError(t, err)
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName), testFileSize, client)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName), testFileSize, client)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.Error(t, err)
			_, err = client.Stat(testFileName)
			assert.Error(t, err)
			err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName+"1"), testFileSize, client)
			assert.Error(t, err)
			_, err = client.Stat(path.Join(vdirPath1, testFileName+"1"))
			assert.Error(t, err)
			err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName+"1"), testFileSize, client)
			assert.Error(t, err)
			_, err = client.Stat(path.Join(vdirPath2, testFileName+"1"))
			assert.Error(t, err)
			err = client.Remove(path.Join(vdirPath1, testFileName))
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName), testFileSize, client)
			assert.Error(t, err)
			// now test renames
			err = client.Rename(testFileName, path.Join(vdirPath1, testFileName))
			assert.NoError(t, err)
			err = client.Rename(path.Join(vdirPath1, testFileName), path.Join(vdirPath1, testFileName+".rename"))
			assert.NoError(t, err)
			err = client.Rename(path.Join(vdirPath2, testFileName), path.Join(vdirPath2, testFileName+".rename"))
			assert.NoError(t, err)
			err = client.Rename(path.Join(vdirPath2, testFileName+".rename"), testFileName+".rename")
			assert.Error(t, err)
			err = client.Rename(path.Join(vdirPath2, testFileName+".rename"), path.Join(vdirPath1, testFileName))
			assert.Error(t, err)
			err = client.Rename(path.Join(vdirPath1, testFileName+".rename"), path.Join(vdirPath2, testFileName))
			assert.Error(t, err)
			err = client.Rename(path.Join(vdirPath1, testFileName+".rename"), testFileName)
			assert.Error(t, err)
		}
		_, err = httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
		assert.NoError(t, err)
		_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
		err = os.RemoveAll(mappedPath1)
		assert.NoError(t, err)
		err = os.RemoveAll(mappedPath2)
		assert.NoError(t, err)
	}
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
}

func TestSFTPLoopSimple(t *testing.T) {
	usePubKey := false
	user1 := getTestSFTPUser(usePubKey)
	user2 := getTestSFTPUser(usePubKey)
	user1.Username += "1"
	user2.Username += "2"
	user1.FsConfig.Provider = sdk.SFTPFilesystemProvider
	user2.FsConfig.Provider = sdk.SFTPFilesystemProvider
	user1.FsConfig.SFTPConfig = vfs.SFTPFsConfig{
		BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
			Endpoint: sftpServerAddr,
			Username: user2.Username,
		},
		Password: kms.NewPlainSecret(defaultPassword),
	}
	user2.FsConfig.SFTPConfig = vfs.SFTPFsConfig{
		BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
			Endpoint: sftpServerAddr,
			Username: user1.Username,
		},
		Password: kms.NewPlainSecret(defaultPassword),
	}
	user1, resp, err := httpdtest.AddUser(user1, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	user2, resp, err = httpdtest.AddUser(user2, http.StatusCreated)
	assert.NoError(t, err, string(resp))

	_, _, err = getSftpClient(user1, usePubKey)
	assert.Error(t, err)
	_, _, err = getSftpClient(user2, usePubKey)
	assert.Error(t, err)

	user1.FsConfig.SFTPConfig.Username = user1.Username
	user1.FsConfig.SFTPConfig.Password = kms.NewPlainSecret(defaultPassword)

	_, _, err = httpdtest.UpdateUser(user1, http.StatusOK, "")
	assert.NoError(t, err)
	_, _, err = getSftpClient(user1, usePubKey)
	assert.Error(t, err)

	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user1.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user2.GetHomeDir())
	assert.NoError(t, err)
}

func TestSFTPLoopVirtualFolders(t *testing.T) {
	usePubKey := false
	sftpFloderName := "sftp"
	user1 := getTestUser(usePubKey)
	user2 := getTestSFTPUser(usePubKey)
	user3 := getTestSFTPUser(usePubKey)
	user1.Username += "1"
	user2.Username += "2"
	user3.Username += "3"

	// user1 is a local account with a virtual SFTP folder to user2
	// user2 has user1 as SFTP fs
	user1.VirtualFolders = append(user1.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: sftpFloderName,
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
	user3.FsConfig.Provider = sdk.SFTPFilesystemProvider
	user3.FsConfig.SFTPConfig = vfs.SFTPFsConfig{
		BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
			Endpoint: sftpServerAddr,
			Username: user1.Username,
		},
		Password: kms.NewPlainSecret(defaultPassword),
	}

	user1, resp, err := httpdtest.AddUser(user1, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	user2, resp, err = httpdtest.AddUser(user2, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	user3, resp, err = httpdtest.AddUser(user3, http.StatusCreated)
	assert.NoError(t, err, string(resp))

	// login will work but /vdir will not be accessible
	conn, client, err := getSftpClient(user1, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		_, err = client.ReadDir("/vdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SFTP loop")
		}
	}
	// now make user2 a local account with an SFTP virtual folder to user1.
	// So we have:
	// user1 -> local account with the SFTP virtual folder /vdir to user2
	// user2 -> local account with the SFTP virtual folder /vdir2 to user3
	// user3 -> sftp user with user1 as fs
	user2.FsConfig.Provider = sdk.LocalFilesystemProvider
	user2.FsConfig.SFTPConfig = vfs.SFTPFsConfig{}
	user2.VirtualFolders = append(user2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: sftpFloderName,
			FsConfig: vfs.Filesystem{
				Provider: sdk.SFTPFilesystemProvider,
				SFTPConfig: vfs.SFTPFsConfig{
					BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
						Endpoint: sftpServerAddr,
						Username: user3.Username,
					},
					Password: kms.NewPlainSecret(defaultPassword),
				},
			},
		},
		VirtualPath: "/vdir2",
	})
	user2, _, err = httpdtest.UpdateUser(user2, http.StatusOK, "")
	assert.NoError(t, err)

	// login will work but /vdir will not be accessible
	conn, client, err = getSftpClient(user1, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		_, err = client.ReadDir("/vdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SFTP loop")
		}
	}

	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user1.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user2, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user2.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user3, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user3.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: sftpFloderName}, http.StatusOK)
	assert.NoError(t, err)
}

func TestNestedVirtualFolders(t *testing.T) {
	usePubKey := true
	baseUser, resp, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err, string(resp))
	u := getTestSFTPUser(usePubKey)
	u.QuotaFiles = 1000
	mappedPathCrypt := filepath.Join(os.TempDir(), "crypt")
	folderNameCrypt := filepath.Base(mappedPathCrypt)
	vdirCryptPath := "/vdir/crypt"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderNameCrypt,
			FsConfig: vfs.Filesystem{
				Provider: sdk.CryptedFilesystemProvider,
				CryptConfig: vfs.CryptFsConfig{
					Passphrase: kms.NewPlainSecret(defaultPassword),
				},
			},
			MappedPath: mappedPathCrypt,
		},
		VirtualPath: vdirCryptPath,
		QuotaFiles:  100,
	})
	mappedPath := filepath.Join(os.TempDir(), "local")
	folderName := filepath.Base(mappedPath)
	vdirPath := "/vdir/local"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	mappedPathNested := filepath.Join(os.TempDir(), "nested")
	folderNameNested := filepath.Base(mappedPathNested)
	vdirNestedPath := "/vdir/crypt/nested"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderNameNested,
			MappedPath: mappedPathNested,
		},
		VirtualPath: vdirNestedPath,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	user, resp, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		expectedQuotaSize := int64(0)
		expectedQuotaFiles := 0
		fileSize := int64(32765)
		err = writeSFTPFile(testFileName, fileSize, client)
		assert.NoError(t, err)
		expectedQuotaSize += fileSize
		expectedQuotaFiles++
		fileSize = 38764
		err = writeSFTPFile(path.Join("/vdir", testFileName), fileSize, client)
		assert.NoError(t, err)
		expectedQuotaSize += fileSize
		expectedQuotaFiles++
		fileSize = 18769
		err = writeSFTPFile(path.Join(vdirPath, testFileName), fileSize, client)
		assert.NoError(t, err)
		expectedQuotaSize += fileSize
		expectedQuotaFiles++
		fileSize = 27658
		err = writeSFTPFile(path.Join(vdirNestedPath, testFileName), fileSize, client)
		assert.NoError(t, err)
		expectedQuotaSize += fileSize
		expectedQuotaFiles++
		fileSize = 39765
		err = writeSFTPFile(path.Join(vdirCryptPath, testFileName), fileSize, client)
		assert.NoError(t, err)

		userGet, _, err := httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, userGet.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, userGet.UsedQuotaSize)

		folderGet, _, err := httpdtest.GetFolderByName(folderNameCrypt, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, folderGet.UsedQuotaSize, fileSize)
		assert.Equal(t, 1, folderGet.UsedQuotaFiles)

		folderGet, _, err = httpdtest.GetFolderByName(folderName, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(18769), folderGet.UsedQuotaSize)
		assert.Equal(t, 1, folderGet.UsedQuotaFiles)

		folderGet, _, err = httpdtest.GetFolderByName(folderNameNested, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(27658), folderGet.UsedQuotaSize)
		assert.Equal(t, 1, folderGet.UsedQuotaFiles)

		files, err := client.ReadDir("/")
		if assert.NoError(t, err) {
			assert.Len(t, files, 2)
		}
		info, err := client.Stat("vdir")
		if assert.NoError(t, err) {
			assert.True(t, info.IsDir())
		}
		files, err = client.ReadDir("/vdir")
		if assert.NoError(t, err) {
			assert.Len(t, files, 3)
		}
		files, err = client.ReadDir(vdirCryptPath)
		if assert.NoError(t, err) {
			assert.Len(t, files, 2)
		}
		info, err = client.Stat(vdirNestedPath)
		if assert.NoError(t, err) {
			assert.True(t, info.IsDir())
		}
		// finally add some files directly using os method and then check quota
		fName := "testfile"
		fileSize = 123456
		err = createTestFile(filepath.Join(baseUser.HomeDir, fName), fileSize)
		assert.NoError(t, err)
		expectedQuotaSize += fileSize
		expectedQuotaFiles++
		fileSize = 8765
		err = createTestFile(filepath.Join(mappedPath, fName), fileSize)
		assert.NoError(t, err)
		expectedQuotaSize += fileSize
		expectedQuotaFiles++
		fileSize = 98751
		err = createTestFile(filepath.Join(mappedPathNested, fName), fileSize)
		assert.NoError(t, err)
		expectedQuotaSize += fileSize
		expectedQuotaFiles++
		err = createTestFile(filepath.Join(mappedPathCrypt, fName), fileSize)
		assert.NoError(t, err)
		_, err = httpdtest.StartQuotaScan(user, http.StatusAccepted)
		assert.NoError(t, err)
		assert.Eventually(t, func() bool {
			scans, _, err := httpdtest.GetQuotaScans(http.StatusOK)
			if err == nil {
				return len(scans) == 0
			}
			return false
		}, 1*time.Second, 50*time.Millisecond)

		userGet, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, userGet.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, userGet.UsedQuotaSize)

		// the crypt folder is not included within user quota so we need to do a separate scan
		_, err = httpdtest.StartFolderQuotaScan(vfs.BaseVirtualFolder{Name: folderNameCrypt}, http.StatusAccepted)
		assert.NoError(t, err)
		assert.Eventually(t, func() bool {
			scans, _, err := httpdtest.GetFoldersQuotaScans(http.StatusOK)
			if err == nil {
				return len(scans) == 0
			}
			return false
		}, 1*time.Second, 50*time.Millisecond)
		folderGet, _, err = httpdtest.GetFolderByName(folderNameCrypt, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, folderGet.UsedQuotaSize, int64(39765+98751))
		assert.Equal(t, 2, folderGet.UsedQuotaFiles)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderNameCrypt}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderNameNested}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(baseUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(baseUser.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPathCrypt)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPathNested)
	assert.NoError(t, err)
}

func TestTruncateQuotaLimits(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaSize = 20
	mappedPath := filepath.Join(os.TempDir(), "mapped")
	folderName := filepath.Base(mappedPath)
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	vdirPath := "/vmapped"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
		QuotaFiles:  10,
	})
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	u.QuotaSize = 20
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			data := []byte("test data")
			f, err := client.OpenFile(testFileName, os.O_WRONLY|os.O_CREATE)
			if assert.NoError(t, err) {
				n, err := f.Write(data)
				assert.NoError(t, err)
				assert.Equal(t, len(data), n)
				err = f.Truncate(2)
				assert.NoError(t, err)
				expectedQuotaFiles := 0
				expectedQuotaSize := int64(2)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
				assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
				_, err = f.Seek(expectedQuotaSize, io.SeekStart)
				assert.NoError(t, err)
				n, err = f.Write(data)
				assert.NoError(t, err)
				assert.Equal(t, len(data), n)
				err = f.Truncate(5)
				assert.NoError(t, err)
				expectedQuotaSize = int64(5)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
				assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
				_, err = f.Seek(expectedQuotaSize, io.SeekStart)
				assert.NoError(t, err)
				n, err = f.Write(data)
				assert.NoError(t, err)
				assert.Equal(t, len(data), n)
				err = f.Close()
				assert.NoError(t, err)
				expectedQuotaFiles = 1
				expectedQuotaSize = int64(5) + int64(len(data))
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
				assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
			}
			// now truncate by path
			err = client.Truncate(testFileName, 5)
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 1, user.UsedQuotaFiles)
			assert.Equal(t, int64(5), user.UsedQuotaSize)
			// now open an existing file without truncate it, quota should not change
			f, err = client.OpenFile(testFileName, os.O_WRONLY)
			if assert.NoError(t, err) {
				err = f.Close()
				assert.NoError(t, err)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 1, user.UsedQuotaFiles)
				assert.Equal(t, int64(5), user.UsedQuotaSize)
			}
			// open the file truncating it
			f, err = client.OpenFile(testFileName, os.O_WRONLY|os.O_TRUNC)
			if assert.NoError(t, err) {
				err = f.Close()
				assert.NoError(t, err)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 1, user.UsedQuotaFiles)
				assert.Equal(t, int64(0), user.UsedQuotaSize)
			}
			// now test max write size
			f, err = client.OpenFile(testFileName, os.O_WRONLY)
			if assert.NoError(t, err) {
				n, err := f.Write(data)
				assert.NoError(t, err)
				assert.Equal(t, len(data), n)
				err = f.Truncate(11)
				assert.NoError(t, err)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 1, user.UsedQuotaFiles)
				assert.Equal(t, int64(11), user.UsedQuotaSize)
				_, err = f.Seek(int64(11), io.SeekStart)
				assert.NoError(t, err)
				n, err = f.Write(data)
				assert.NoError(t, err)
				assert.Equal(t, len(data), n)
				err = f.Truncate(5)
				assert.NoError(t, err)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 1, user.UsedQuotaFiles)
				assert.Equal(t, int64(5), user.UsedQuotaSize)
				_, err = f.Seek(int64(5), io.SeekStart)
				assert.NoError(t, err)
				n, err = f.Write(data)
				assert.NoError(t, err)
				assert.Equal(t, len(data), n)
				err = f.Truncate(12)
				assert.NoError(t, err)
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 1, user.UsedQuotaFiles)
				assert.Equal(t, int64(12), user.UsedQuotaSize)
				_, err = f.Seek(int64(12), io.SeekStart)
				assert.NoError(t, err)
				_, err = f.Write(data)
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), common.ErrQuotaExceeded.Error())
				}
				err = f.Close()
				assert.Error(t, err)
				// the file is deleted
				user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, 0, user.UsedQuotaFiles)
				assert.Equal(t, int64(0), user.UsedQuotaSize)
			}

			if user.Username == defaultUsername {
				// basic test inside a virtual folder
				vfileName := path.Join(vdirPath, testFileName)
				f, err = client.OpenFile(vfileName, os.O_WRONLY|os.O_CREATE)
				if assert.NoError(t, err) {
					n, err := f.Write(data)
					assert.NoError(t, err)
					assert.Equal(t, len(data), n)
					err = f.Truncate(2)
					assert.NoError(t, err)
					expectedQuotaFiles := 0
					expectedQuotaSize := int64(2)
					fold, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
					assert.NoError(t, err)
					assert.Equal(t, expectedQuotaSize, fold.UsedQuotaSize)
					assert.Equal(t, expectedQuotaFiles, fold.UsedQuotaFiles)
					err = f.Close()
					assert.NoError(t, err)
					expectedQuotaFiles = 1
					fold, _, err = httpdtest.GetFolderByName(folderName, http.StatusOK)
					assert.NoError(t, err)
					assert.Equal(t, expectedQuotaSize, fold.UsedQuotaSize)
					assert.Equal(t, expectedQuotaFiles, fold.UsedQuotaFiles)
				}
				err = client.Truncate(vfileName, 1)
				assert.NoError(t, err)
				fold, _, err := httpdtest.GetFolderByName(folderName, http.StatusOK)
				assert.NoError(t, err)
				assert.Equal(t, int64(1), fold.UsedQuotaSize)
				assert.Equal(t, 1, fold.UsedQuotaFiles)
				// cleanup
				err = os.RemoveAll(user.GetHomeDir())
				assert.NoError(t, err)
				_, err = httpdtest.RemoveUser(user, http.StatusOK)
				assert.NoError(t, err)
				user.Password = defaultPassword
				user.ID = 0
				user.CreatedAt = 0
				user.QuotaSize = 0
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
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestVirtualFoldersQuotaRenameOverwrite(t *testing.T) {
	usePubKey := true
	testFileSize := int64(131072)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize1 := int64(65537)
	testFileName1 := "test_file1.dat"
	testFilePath1 := filepath.Join(homeBasePath, testFileName1)
	err := createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = createTestFile(testFilePath1, testFileSize1)
	assert.NoError(t, err)
	u := getTestUser(usePubKey)
	u.QuotaFiles = 0
	u.QuotaSize = 0
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	mappedPath3 := filepath.Join(os.TempDir(), "vdir3")
	folderName3 := filepath.Base(mappedPath3)
	vdirPath3 := "/vdir3"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  2,
		QuotaSize:   0,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
			Name:       folderName2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  0,
		QuotaSize:   testFileSize + testFileSize1 + 1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName3,
			MappedPath: mappedPath3,
		},
		VirtualPath: vdirPath3,
		QuotaFiles:  2,
		QuotaSize:   testFileSize * 2,
	})
	err = os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath3, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath3, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath3, testFileName+"1"), testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName, path.Join(vdirPath1, testFileName+".rename"))
		assert.Error(t, err)
		// we overwrite an existing file and we have unlimited size
		err = client.Rename(testFileName, path.Join(vdirPath1, testFileName))
		assert.NoError(t, err)
		// we have no space and we try to overwrite a bigger file with a smaller one, this should succeed
		err = client.Rename(testFileName1, path.Join(vdirPath2, testFileName))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		// we have no space and we try to overwrite a smaller file with a bigger one, this should fail
		err = client.Rename(testFileName, path.Join(vdirPath2, testFileName1))
		assert.Error(t, err)
		fi, err := client.Stat(path.Join(vdirPath1, testFileName1))
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize1, fi.Size())
		}
		// we are overquota inside vdir3 size 2/2 and size 262144/262144
		err = client.Rename(path.Join(vdirPath1, testFileName1), path.Join(vdirPath3, testFileName1+".rename"))
		assert.Error(t, err)
		// we overwrite an existing file and we have enough size
		err = client.Rename(path.Join(vdirPath1, testFileName1), path.Join(vdirPath3, testFileName))
		assert.NoError(t, err)
		testFileName2 := "test_file2.dat"
		testFilePath2 := filepath.Join(homeBasePath, testFileName2)
		err = createTestFile(testFilePath2, testFileSize+testFileSize1)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath2, testFileName2, testFileSize+testFileSize1, client)
		assert.NoError(t, err)
		// we overwrite an existing file and we haven't enough size
		err = client.Rename(testFileName2, path.Join(vdirPath3, testFileName))
		assert.Error(t, err)
		err = os.Remove(testFilePath2)
		assert.NoError(t, err)
		// now remove a file from vdir3, create a dir with 2 files and try to rename it in vdir3
		// this will fail since the rename will result in 3 files inside vdir3 and quota limits only
		// allow 2 total files there
		err = client.Remove(path.Join(vdirPath3, testFileName+"1"))
		assert.NoError(t, err)
		aDir := "a dir"
		err = client.Mkdir(aDir)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(aDir, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(aDir, testFileName1+"1"), testFileSize1, client)
		assert.NoError(t, err)
		err = client.Rename(aDir, path.Join(vdirPath3, aDir))
		assert.Error(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName3}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath3)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
}

func TestVirtualFoldersQuotaValues(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vdir1" //nolint:goconst
	folderName1 := filepath.Base(mappedPath1)
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2" //nolint:goconst
	folderName2 := filepath.Base(mappedPath2)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileSize := int64(131072)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		// we copy the same file two times to test quota update on file overwrite
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		expectedQuotaFiles := 2
		expectedQuotaSize := testFileSize * 2
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)

		err = client.Remove(path.Join(vdirPath1, testFileName))
		assert.NoError(t, err)
		err = client.Remove(path.Join(vdirPath2, testFileName))
		assert.NoError(t, err)

		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestQuotaRenameInsideSameVirtualFolder(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vdir1"
	folderName1 := filepath.Base(mappedPath1)
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	folderName2 := filepath.Base(mappedPath2)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileName1 := "test_file1.dat"
		testFileSize := int64(131072)
		testFileSize1 := int64(65535)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFilePath1 := filepath.Join(homeBasePath, testFileName1)
		dir1 := "dir1" //nolint:goconst
		dir2 := "dir2" //nolint:goconst
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = createTestFile(testFilePath1, testFileSize1)
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath1, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath2, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// initial files:
		// - vdir1/dir1/testFileName
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		//
		// rename a file inside vdir1 it is included inside user quota, so we have:
		// - vdir1/dir1/testFileName.rename
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		err = client.Rename(path.Join(vdirPath1, dir1, testFileName), path.Join(vdirPath1, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file inside vdir2, it isn't included inside user quota, so we have:
		// - vdir1/dir1/testFileName.rename
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName.rename
		// - vdir2/dir2/testFileName1
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName), path.Join(vdirPath2, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file inside vdir2 overwriting an existing, we now have:
		// - vdir1/dir1/testFileName.rename
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName.rename (initial testFileName1)
		err = client.Rename(path.Join(vdirPath2, dir2, testFileName1), path.Join(vdirPath2, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file inside vdir1 overwriting an existing, we now have:
		// - vdir1/dir1/testFileName.rename (initial testFileName1)
		// - vdir2/dir1/testFileName.rename (initial testFileName1)
		err = client.Rename(path.Join(vdirPath1, dir2, testFileName1), path.Join(vdirPath1, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// rename a directory inside the same virtual folder, quota should not change
		err = client.RemoveDirectory(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.RemoveDirectory(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirPath1, dir1), path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirPath2, dir1), path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestQuotaRenameBetweenVirtualFolder(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileName1 := "test_file1.dat"
		testFileSize := int64(131072)
		testFileSize1 := int64(65535)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFilePath1 := filepath.Join(homeBasePath, testFileName1)
		dir1 := "dir1"
		dir2 := "dir2"
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = createTestFile(testFilePath1, testFileSize1)
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath1, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath2, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		// initial files:
		// - vdir1/dir1/testFileName
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		//
		// rename a file from vdir1 to vdir2, vdir1 is included inside user quota, so we have:
		// - vdir1/dir1/testFileName
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		// - vdir2/dir1/testFileName1.rename
		err = client.Rename(path.Join(vdirPath1, dir2, testFileName1), path.Join(vdirPath2, dir1, testFileName1+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 3, f.UsedQuotaFiles)
		// rename a file from vdir2 to vdir1, vdir2 is not included inside user quota, so we have:
		// - vdir1/dir1/testFileName
		// - vdir1/dir2/testFileName.rename
		// - vdir2/dir2/testFileName1
		// - vdir2/dir1/testFileName1.rename
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName), path.Join(vdirPath1, dir2, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize*2, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1*2, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file from vdir1 to vdir2 overwriting an existing file, vdir1 is included inside user quota, so we have:
		// - vdir1/dir2/testFileName.rename
		// - vdir2/dir2/testFileName1 (is the initial testFileName)
		// - vdir2/dir1/testFileName1.rename
		err = client.Rename(path.Join(vdirPath1, dir1, testFileName), path.Join(vdirPath2, dir2, testFileName1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1+testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file from vdir2 to vdir1 overwriting an existing file, vdir2 is not included inside user quota, so we have:
		// - vdir1/dir2/testFileName.rename (is the initial testFileName1)
		// - vdir2/dir2/testFileName1 (is the initial testFileName)
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName1+".rename"), path.Join(vdirPath1, dir2, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)

		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, dir2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath2, dir2, testFileName), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath2, dir2, testFileName+"1.dupl"), testFileSize1, client)
		assert.NoError(t, err)
		err = client.RemoveDirectory(path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		err = client.RemoveDirectory(path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		// - vdir1/dir2/testFileName.rename (initial testFileName1)
		// - vdir1/dir2/testFileName
		// - vdir2/dir2/testFileName1 (initial testFileName)
		// - vdir2/dir2/testFileName (initial testFileName1)
		// - vdir2/dir2/testFileName1.dupl
		// rename directories between the two virtual folders
		err = client.Rename(path.Join(vdirPath2, dir2), path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 5, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1*3+testFileSize*2, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1*3+testFileSize*2, f.UsedQuotaSize)
		assert.Equal(t, 5, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		// now move on vpath2
		err = client.Rename(path.Join(vdirPath1, dir2), path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1*2+testFileSize, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1*2+testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 3, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestQuotaRenameFromVirtualFolder(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileName1 := "test_file1.dat"
		testFileSize := int64(131072)
		testFileSize1 := int64(65535)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFilePath1 := filepath.Join(homeBasePath, testFileName1)
		dir1 := "dir1"
		dir2 := "dir2"
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = createTestFile(testFilePath1, testFileSize1)
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath1, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath2, dir2, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		// initial files:
		// - vdir1/dir1/testFileName
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		//
		// rename a file from vdir1 to the user home dir, vdir1 is included in user quota so we have:
		// - testFileName
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		// - vdir2/dir2/testFileName1
		err = client.Rename(path.Join(vdirPath1, dir1, testFileName), path.Join(testFileName))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		// rename a file from vdir2 to the user home dir, vdir2 is not included in user quota so we have:
		// - testFileName
		// - testFileName1
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		err = client.Rename(path.Join(vdirPath2, dir2, testFileName1), path.Join(testFileName1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// rename a file from vdir1 to the user home dir overwriting an existing file, vdir1 is included in user quota so we have:
		// - testFileName (initial testFileName1)
		// - testFileName1
		// - vdir2/dir1/testFileName
		err = client.Rename(path.Join(vdirPath1, dir2, testFileName1), path.Join(testFileName))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// rename a file from vdir2 to the user home dir overwriting an existing file, vdir2 is not included in user quota so we have:
		// - testFileName (initial testFileName1)
		// - testFileName1 (initial testFileName)
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName), path.Join(testFileName1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		// dir rename
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath1, dir1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath2, dir1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		// - testFileName (initial testFileName1)
		// - testFileName1 (initial testFileName)
		// - vdir1/dir1/testFileName
		// - vdir1/dir1/testFileName1
		// - dir1/testFileName
		// - dir1/testFileName1
		err = client.Rename(path.Join(vdirPath2, dir1), dir1)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 6, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*3+testFileSize1*3, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		// - testFileName (initial testFileName1)
		// - testFileName1 (initial testFileName)
		// - dir2/testFileName
		// - dir2/testFileName1
		// - dir1/testFileName
		// - dir1/testFileName1
		err = client.Rename(path.Join(vdirPath1, dir1), dir2)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 6, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*3+testFileSize1*3, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		assert.Equal(t, 0, f.UsedQuotaFiles)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestQuotaRenameToVirtualFolder(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileName1 := "test_file1.dat"
		testFileSize := int64(131072)
		testFileSize1 := int64(65535)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFilePath1 := filepath.Join(homeBasePath, testFileName1)
		dir1 := "dir1"
		dir2 := "dir2"
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = createTestFile(testFilePath1, testFileSize1)
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		// initial files:
		// - testFileName
		// - testFileName1
		//
		// rename a file from user home dir to vdir1, vdir1 is included in user quota so we have:
		// - testFileName
		// - /vdir1/dir1/testFileName1
		err = client.Rename(testFileName1, path.Join(vdirPath1, dir1, testFileName1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// rename a file from user home dir to vdir2, vdir2 is not included in user quota so we have:
		// - /vdir2/dir1/testFileName
		// - /vdir1/dir1/testFileName1
		err = client.Rename(testFileName, path.Join(vdirPath2, dir1, testFileName))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// upload two new files to the user home dir so we have:
		// - testFileName
		// - testFileName1
		// - /vdir1/dir1/testFileName1
		// - /vdir2/dir1/testFileName
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1+testFileSize1, user.UsedQuotaSize)
		// rename a file from user home dir to vdir1 overwriting an existing file, vdir1 is included in user quota so we have:
		// - testFileName1
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName
		err = client.Rename(testFileName, path.Join(vdirPath1, dir1, testFileName1))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// rename a file from user home dir to vdir2 overwriting an existing file, vdir2 is not included in user quota so we have:
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName (initial testFileName1)
		err = client.Rename(testFileName1, path.Join(vdirPath2, dir1, testFileName))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)

		err = client.Mkdir(dir1)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(dir1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		// - /dir1/testFileName
		// - /dir1/testFileName1
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName (initial testFileName1)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		// - /vdir1/adir/testFileName
		// - /vdir1/adir/testFileName1
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName (initial testFileName1)
		err = client.Rename(dir1, path.Join(vdirPath1, "adir"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize*2+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 3, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		err = client.Mkdir(dir1)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(dir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(dir1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		// - /vdir1/adir/testFileName
		// - /vdir1/adir/testFileName1
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName (initial testFileName1)
		// - /vdir2/adir/testFileName
		// - /vdir2/adir/testFileName1
		err = client.Rename(dir1, path.Join(vdirPath2, "adir"))
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1, user.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize*2+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 3, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize1*2+testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 3, f.UsedQuotaFiles)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestVirtualFoldersLink(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		// quota is unlimited and excluded from user's one
		QuotaFiles: 0,
		QuotaSize:  0,
	})
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileSize := int64(131072)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testDir := "adir"
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, testDir))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, testDir))
		assert.NoError(t, err)
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		err = client.Symlink(path.Join(vdirPath1, testFileName), path.Join(vdirPath1, testFileName+".link"))
		assert.NoError(t, err)
		err = client.Symlink(path.Join(vdirPath1, testFileName), path.Join(vdirPath1, testDir, testFileName+".link"))
		assert.NoError(t, err)
		err = client.Symlink(path.Join(vdirPath2, testFileName), path.Join(vdirPath2, testFileName+".link"))
		assert.NoError(t, err)
		err = client.Symlink(path.Join(vdirPath2, testFileName), path.Join(vdirPath2, testDir, testFileName+".link"))
		assert.NoError(t, err)
		err = client.Symlink(testFileName, path.Join(vdirPath1, testFileName+".link1"))
		assert.Error(t, err)
		err = client.Symlink(testFileName, path.Join(vdirPath1, testDir, testFileName+".link1"))
		assert.Error(t, err)
		err = client.Symlink(testFileName, path.Join(vdirPath2, testFileName+".link1"))
		assert.Error(t, err)
		err = client.Symlink(testFileName, path.Join(vdirPath2, testDir, testFileName+".link1"))
		assert.Error(t, err)
		err = client.Symlink(path.Join(vdirPath1, testFileName), testFileName+".link1")
		assert.Error(t, err)
		err = client.Symlink(path.Join(vdirPath2, testFileName), testFileName+".link1")
		assert.Error(t, err)
		err = client.Symlink(path.Join(vdirPath1, testFileName), path.Join(vdirPath2, testDir, testFileName+".link1"))
		assert.Error(t, err)
		err = client.Symlink(path.Join(vdirPath2, testFileName), path.Join(vdirPath1, testFileName+".link1"))
		assert.Error(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestVirtualFolderQuotaScan(t *testing.T) {
	mappedPath := filepath.Join(os.TempDir(), "mapped_dir")
	folderName := filepath.Base(mappedPath)
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	testFileSize := int64(65535)
	testFilePath := filepath.Join(mappedPath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	expectedQuotaSize := testFileSize
	expectedQuotaFiles := 1
	folder, _, err := httpdtest.AddFolder(vfs.BaseVirtualFolder{
		Name:       folderName,
		MappedPath: mappedPath,
	}, http.StatusCreated)
	assert.NoError(t, err)
	_, err = httpdtest.StartFolderQuotaScan(folder, http.StatusAccepted)
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		scans, _, err := httpdtest.GetFoldersQuotaScans(http.StatusOK)
		if err == nil {
			return len(scans) == 0
		}
		return false
	}, 1*time.Second, 50*time.Millisecond)
	folder, _, err = httpdtest.GetFolderByName(folderName, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, folder.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, folder.UsedQuotaSize)
	_, err = httpdtest.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestVFolderMultipleQuotaScan(t *testing.T) {
	folderName := "folder_name"
	res := common.QuotaScans.AddVFolderQuotaScan(folderName)
	assert.True(t, res)
	res = common.QuotaScans.AddVFolderQuotaScan(folderName)
	assert.False(t, res)
	res = common.QuotaScans.RemoveVFolderQuotaScan(folderName)
	assert.True(t, res)
	activeScans := common.QuotaScans.GetVFoldersQuotaScans()
	assert.Len(t, activeScans, 0)
	res = common.QuotaScans.RemoveVFolderQuotaScan(folderName)
	assert.False(t, res)
}

func TestVFolderQuotaSize(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	testFileSize := int64(131072)
	u.QuotaFiles = 1
	u.QuotaSize = testFileSize + 1
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vpath1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vpath2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  1,
		QuotaSize:   testFileSize * 2,
	})
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		// vdir1 is included in the user quota so upload must fail
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.Error(t, err)
		// upload to vdir2 must work, it has its own quota
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		// now vdir2 is over quota
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName+".quota"), testFileSize, client)
		assert.Error(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		// remove a file
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 0, user.UsedQuotaFiles)
		assert.Equal(t, int64(0), user.UsedQuotaSize)
		// upload to vdir1 must work now
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)

		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, f.UsedQuotaSize)
		assert.Equal(t, 1, f.UsedQuotaFiles)
	}
	// now create another user with the same shared folder but a different quota limit
	u.Username = defaultUsername + "1"
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  10,
		QuotaSize:   testFileSize*2 + 1,
	})
	user1, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user1, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName+".quota"), testFileSize, client)
		assert.NoError(t, err)
		// the folder is now over quota for size but not for files
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName+".quota1"), testFileSize, client)
		assert.Error(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestMissingFile(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile("missing_file", localDownloadPath, 0, client)
		assert.Error(t, err, "download missing file must fail")
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestOpenError(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = os.Chmod(user.GetHomeDir(), 0001)
		assert.NoError(t, err)
		_, err = client.ReadDir(".")
		assert.Error(t, err, "read dir must fail if we have no filesystem read permissions")
		err = os.Chmod(user.GetHomeDir(), os.ModePerm)
		assert.NoError(t, err)
		testFileSize := int64(65535)
		testFilePath := filepath.Join(user.GetHomeDir(), testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		_, err = client.Stat(testFileName)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		err = os.Chmod(testFilePath, 0001)
		assert.NoError(t, err)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.Error(t, err, "file download must fail if we have no filesystem read permissions")
		err = sftpUploadFile(localDownloadPath, testFileName, testFileSize, client)
		assert.Error(t, err, "upload must fail if we have no filesystem write permissions")
		testDir := "test"
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = createTestFile(filepath.Join(user.GetHomeDir(), testDir, testFileName), testFileSize)
		assert.NoError(t, err)
		err = os.Chmod(user.GetHomeDir(), 0000)
		assert.NoError(t, err)
		_, err = client.Lstat(testFileName)
		assert.Error(t, err, "file stat must fail if we have no filesystem read permissions")
		err = sftpUploadFile(localDownloadPath, path.Join(testDir, testFileName), testFileSize, client)
		assert.ErrorIs(t, err, os.ErrPermission)
		_, err = client.ReadLink(testFileName)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = client.Remove(testFileName)
		assert.ErrorIs(t, err, os.ErrPermission)
		err = os.Chmod(user.GetHomeDir(), os.ModePerm)
		assert.NoError(t, err)
		err = os.Chmod(filepath.Join(user.GetHomeDir(), testDir), 0000)
		assert.NoError(t, err)
		err = client.Rename(testFileName, path.Join(testDir, testFileName))
		assert.True(t, os.IsPermission(err))
		err = os.Chmod(filepath.Join(user.GetHomeDir(), testDir), os.ModePerm)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestOverwriteDirWithFile(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileSize := int64(65535)
		testDirName := "test_dir" //nolint:goconst
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = client.Mkdir(testDirName)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testDirName, testFileSize, client)
		assert.Error(t, err, "copying a file over an existing dir must fail")
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testDirName)
		assert.Error(t, err, "rename a file over an existing dir must fail")
		err = client.RemoveDirectory(testDirName)
		assert.NoError(t, err)
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestHashedPasswords(t *testing.T) {
	usePubKey := false
	plainPwd := "password"
	pwdMapping := make(map[string]string)
	pwdMapping["$argon2id$v=19$m=65536,t=3,p=2$xtcO/oRkC8O2Tn+mryl2mw$O7bn24f2kuSGRMi9s5Cm61Wqd810px1jDsAasrGWkzQ"] = plainPwd
	pwdMapping["$pbkdf2-sha1$150000$DveVjgYUD05R$X6ydQZdyMeOvpgND2nqGR/0GGic="] = plainPwd
	pwdMapping["$pbkdf2-sha256$150000$E86a9YMX3zC7$R5J62hsSq+pYw00hLLPKBbcGXmq7fj5+/M0IFoYtZbo="] = plainPwd
	pwdMapping["$pbkdf2-sha512$150000$dsu7T5R3IaVQ$1hFXPO1ntRBcoWkSLKw+s4sAP09Xtu4Ya7CyxFq64jM9zdUg8eRJVr3NcR2vQgb0W9HHvZaILHsL4Q/Vr6arCg=="] = plainPwd
	pwdMapping["$1$b5caebda$VODr/nyhGWgZaY8sJ4x05."] = plainPwd
	pwdMapping["$2a$14$ajq8Q7fbtFRQvXpdCq7Jcuy.Rx1h/L4J60Otx.gyNLbAYctGMJ9tK"] = "secret"
	pwdMapping["$6$459ead56b72e44bc$uog86fUxscjt28BZxqFBE2pp2QD8P/1e98MNF75Z9xJfQvOckZnQ/1YJqiq1XeytPuDieHZvDAMoP7352ELkO1"] = "secret"
	pwdMapping["$apr1$OBWLeSme$WoJbB736e7kKxMBIAqilb1"] = plainPwd
	pwdMapping["{MD5}5f4dcc3b5aa765d61d8327deb882cf99"] = plainPwd

	for pwd, clearPwd := range pwdMapping {
		u := getTestUser(usePubKey)
		u.Password = pwd
		user, _, err := httpdtest.AddUser(u, http.StatusCreated)
		assert.NoError(t, err)
		user.Password = ""
		userGetInitial, _, err := httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		user, err = dataprovider.UserExists(user.Username)
		assert.NoError(t, err)
		assert.Equal(t, pwd, user.Password)
		user.Password = clearPwd
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err, "unable to login with password %#v", pwd) {
			defer conn.Close()
			defer client.Close()
			assert.NoError(t, checkBasicSFTP(client))
		}
		user.Password = pwd
		conn, client, err = getSftpClient(user, usePubKey)
		if !assert.Error(t, err, "login with wrong password must fail") {
			client.Close()
			conn.Close()
		}
		// the password must converted to bcrypt and we should still be able to login
		user, err = dataprovider.UserExists(user.Username)
		assert.NoError(t, err)
		assert.True(t, strings.HasPrefix(user.Password, "$2a$"))
		// update the user to invalidate the cached password and force a new check
		user.Password = ""
		userGet, _, err := httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		userGetInitial.LastLogin = userGet.LastLogin
		userGetInitial.UpdatedAt = userGet.UpdatedAt
		assert.Equal(t, userGetInitial, userGet)
		// login should still work
		user.Password = clearPwd
		conn, client, err = getSftpClient(user, usePubKey)
		if assert.NoError(t, err, "unable to login with password %#v", pwd) {
			defer conn.Close()
			defer client.Close()
			assert.NoError(t, checkBasicSFTP(client))
		}
		_, err = httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
	}
}

func TestPasswordsHashPbkdf2Sha256_389DS(t *testing.T) {
	pbkdf389dsPwd := "{PBKDF2_SHA256}AAAIAMZIKG4ie44zJY4HOXI+upFR74PzWLUQV63jg+zzkbEjCK3N4qW583WF7EdcpeoOMQ4HY3aWEXB6lnXhXJixbJkU4vVSJkL6YCbU3TrD0qn1uUUVSkaIgAOtmZENitwbhYhiWfEzGyAtFqkFd75P5xhWJEog9XhQKYrR0f7S3WGGZq03JRcLJ460xpU97bE/sWRn7sshgkWzLuyrs0I+XRKmK7FJeaA9zd+1m44Y3IVmZ2YLdKATzjRHAIgpBC6i1TWOcpKJT1+feP1C9hrxH8vU9baw9thNiO8jSHaZlwb//KpJFe0ahVnG/1ubiG8cO0+CCqDqXVJR6Vr4QZxHP+4pwooW+4TP/L+HFdyA1y6z4gKfqYnBsmb3sD1R1TbxfH4btTdvgZAnBk9CmR3QASkFXxeTYsrmNd5+9IAHc6dm"
	pbkdf389dsPwd = pbkdf389dsPwd[15:]
	hashBytes, err := base64.StdEncoding.DecodeString(pbkdf389dsPwd)
	assert.NoError(t, err)
	iterBytes := hashBytes[0:4]
	var iterations int32
	err = binary.Read(bytes.NewBuffer(iterBytes), binary.BigEndian, &iterations)
	assert.NoError(t, err)
	salt := hashBytes[4:68]
	targetKey := hashBytes[68:]
	key := base64.StdEncoding.EncodeToString(targetKey)
	pbkdf2Pwd := fmt.Sprintf("$pbkdf2-b64salt-sha256$%v$%v$%v", iterations, base64.StdEncoding.EncodeToString(salt), key)
	pbkdf2ClearPwd := "password"
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Password = pbkdf2Pwd
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	user.Password = pbkdf2ClearPwd
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Password = pbkdf2Pwd
	conn, client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login with wrong password must fail") {
		client.Close()
		conn.Close()
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermList(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
	u.Permissions["/sub"] = []string{dataprovider.PermCreateSymlinks, dataprovider.PermListItems}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		_, err = client.ReadDir(".")
		assert.Error(t, err, "read remote dir without permission should not succeed")
		_, err = client.Stat("test_file")
		assert.Error(t, err, "stat remote file without permission should not succeed")
		_, err = client.Lstat("test_file")
		assert.Error(t, err, "lstat remote file without permission should not succeed")
		_, err = client.ReadLink("test_link")
		assert.Error(t, err, "read remote link without permission on source dir should not succeed")
		f, err := client.Create(testFileName)
		if assert.NoError(t, err) {
			_, err = f.Write([]byte("content"))
			assert.NoError(t, err)
			err = f.Close()
			assert.NoError(t, err)
		}
		err = client.Mkdir("sub")
		assert.NoError(t, err)
		err = client.Symlink(testFileName, path.Join("/sub", testFileName))
		assert.NoError(t, err)
		_, err = client.ReadLink(path.Join("/sub", testFileName))
		assert.Error(t, err, "read remote link without permission on targe dir should not succeed")
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermDownload(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermUpload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.Error(t, err, "file download without permission should not succeed")
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermUpload(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermDelete, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.Error(t, err, "file upload without permission should not succeed")
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermOverwrite(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.Error(t, err, "file overwrite without permission should not succeed")
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermDelete(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermRename,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Remove(testFileName)
		assert.Error(t, err, "delete without permission should not succeed")
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestPermRename(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileName+".rename")
		assert.True(t, os.IsPermission(err))
		_, err = client.Stat(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestPermRenameOverwrite(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermChmod, dataprovider.PermRename,
		dataprovider.PermChown, dataprovider.PermChtimes}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileName+".rename")
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileName+".rename")
		assert.True(t, os.IsPermission(err))
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermCreateDirs(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.Mkdir("testdir")
		assert.Error(t, err, "mkdir without permission should not succeed")
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestPermSymlink(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermOverwrite, dataprovider.PermChmod, dataprovider.PermChown,
		dataprovider.PermChtimes}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Symlink(testFilePath, testFilePath+".symlink")
		assert.Error(t, err, "symlink without permission should not succeed")
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermChmod(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite,
		dataprovider.PermChown, dataprovider.PermChtimes}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Chmod(testFileName, os.ModePerm)
		assert.Error(t, err, "chmod without permission should not succeed")
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestPermChown(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite,
		dataprovider.PermChmod, dataprovider.PermChtimes}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Chown(testFileName, os.Getuid(), os.Getgid())
		assert.Error(t, err, "chown without permission should not succeed")
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestPermChtimes(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermRename, dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite,
		dataprovider.PermChmod, dataprovider.PermChown}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Chtimes(testFileName, time.Now(), time.Now())
		assert.Error(t, err, "chtimes without permission should not succeed")
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSubDirsUploads(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermChtimes, dataprovider.PermDownload, dataprovider.PermOverwrite}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.Mkdir("subdir")
		assert.NoError(t, err)
		testFileNameSub := "/subdir/test_file_dat"
		testSubFile := filepath.Join(user.GetHomeDir(), "subdir", "file.dat")
		testDir := "testdir"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = createTestFile(testSubFile, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileNameSub, testFileSize, client)
		assert.True(t, os.IsPermission(err))
		err = client.Symlink(testFileName, testFileNameSub+".link")
		assert.True(t, os.IsPermission(err))
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileNameSub+".rename")
		assert.True(t, os.IsPermission(err))
		err = client.Rename(testFileName, testFileName+".rename")
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		// rename overwriting an existing file
		err = client.Rename(testFileName, testFileName+".rename")
		assert.NoError(t, err)
		// now try to overwrite a directory
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testDir)
		assert.Error(t, err)
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = client.Remove(testDir)
		assert.NoError(t, err)
		err = client.Remove(path.Join("/subdir", "file.dat"))
		assert.True(t, os.IsPermission(err))
		err = client.Remove(testFileName + ".rename")
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSubDirsOverwrite(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermOverwrite, dataprovider.PermListItems}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileName := "/subdir/test_file.dat" //nolint:goconst
		testFilePath := filepath.Join(homeBasePath, "test_file.dat")
		testFileSFTPPath := filepath.Join(u.GetHomeDir(), "subdir", "test_file.dat")
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = createTestFile(testFileSFTPPath, 16384)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName+".new", testFileSize, client)
		assert.True(t, os.IsPermission(err))
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSubDirsDownloads(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermChmod, dataprovider.PermUpload, dataprovider.PermListItems}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.Mkdir("subdir")
		assert.NoError(t, err)
		testFileName := "/subdir/test_file.dat"
		testFilePath := filepath.Join(homeBasePath, "test_file.dat")
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		assert.True(t, os.IsPermission(err))
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.True(t, os.IsPermission(err))
		err = client.Chtimes(testFileName, time.Now(), time.Now())
		assert.True(t, os.IsPermission(err))
		err = client.Rename(testFileName, testFileName+".rename")
		assert.True(t, os.IsPermission(err))
		err = client.Symlink(testFileName, testFileName+".link")
		assert.True(t, os.IsPermission(err))
		err = client.Remove(testFileName)
		assert.True(t, os.IsPermission(err))
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermsSubDirsSetstat(t *testing.T) {
	// for setstat we check the parent dir permission if the requested path is a dir
	// otherwise the path permission
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermCreateDirs}
	u.Permissions["/subdir"] = []string{dataprovider.PermAny}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.Mkdir("subdir")
		assert.NoError(t, err)
		testFileName := "/subdir/test_file.dat"
		testFilePath := filepath.Join(homeBasePath, "test_file.dat")
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Chtimes("/subdir/", time.Now(), time.Now())
		assert.True(t, os.IsPermission(err))
		err = client.Chtimes("subdir/", time.Now(), time.Now())
		assert.True(t, os.IsPermission(err))
		err = client.Chtimes(testFileName, time.Now(), time.Now())
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestOpenUnhandledChannel(t *testing.T) {
	u := getTestUser(false)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	config := &ssh.ClientConfig{
		User: user.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Auth: []ssh.AuthMethod{ssh.Password(defaultPassword)},
	}
	conn, err := ssh.Dial("tcp", sftpServerAddr, config)
	if assert.NoError(t, err) {
		_, _, err = conn.OpenChannel("unhandled", nil)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "unknown channel type")
		}
		err = conn.Close()
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestPermsSubDirsCommands(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermCreateDirs}
	u.Permissions["/subdir/otherdir"] = []string{dataprovider.PermListItems, dataprovider.PermDownload}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		err = client.Mkdir("subdir")
		assert.NoError(t, err)
		acmodTime := time.Now()
		err = client.Chtimes("/subdir", acmodTime, acmodTime)
		assert.NoError(t, err)
		_, err = client.Stat("/subdir")
		assert.NoError(t, err)
		_, err = client.ReadDir("/")
		assert.NoError(t, err)
		_, err = client.ReadDir("/subdir")
		assert.True(t, os.IsPermission(err))
		err = client.RemoveDirectory("/subdir/dir")
		assert.True(t, os.IsPermission(err))
		err = client.Mkdir("/subdir/otherdir/dir")
		assert.True(t, os.IsPermission(err))
		err = client.Mkdir("/otherdir")
		assert.NoError(t, err)
		err = client.Mkdir("/subdir/otherdir")
		assert.NoError(t, err)
		err = client.Rename("/otherdir", "/subdir/otherdir/adir")
		assert.True(t, os.IsPermission(err))
		err = client.Symlink("/otherdir", "/subdir/otherdir")
		assert.True(t, os.IsPermission(err))
		err = client.Symlink("/otherdir", "/otherdir_link")
		assert.NoError(t, err)
		err = client.Rename("/otherdir", "/otherdir1")
		assert.NoError(t, err)
		err = client.RemoveDirectory("/otherdir1")
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRootDirCommands(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			err = client.Rename("/", "rootdir")
			assert.True(t, os.IsPermission(err))
			err = client.Symlink("/", "rootdir")
			assert.True(t, os.IsPermission(err))
			err = client.RemoveDirectory("/")
			assert.True(t, os.IsPermission(err))
		}
		if user.Username == defaultUsername {
			err = os.RemoveAll(user.GetHomeDir())
			assert.NoError(t, err)
			_, err = httpdtest.RemoveUser(user, http.StatusOK)
			assert.NoError(t, err)
			user.Password = defaultPassword
			user.ID = 0
			user.CreatedAt = 0
			user.Permissions = make(map[string][]string)
			user.Permissions["/"] = []string{dataprovider.PermAny}
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

func TestRelativePaths(t *testing.T) {
	user := getTestUser(true)
	var path, rel string
	filesystems := []vfs.Fs{vfs.NewOsFs("", user.GetHomeDir(), "")}
	keyPrefix := strings.TrimPrefix(user.GetHomeDir(), "/") + "/"
	s3config := vfs.S3FsConfig{
		BaseS3FsConfig: sdk.BaseS3FsConfig{
			KeyPrefix: keyPrefix,
		},
	}
	s3fs, _ := vfs.NewS3Fs("", user.GetHomeDir(), "", s3config)
	gcsConfig := vfs.GCSFsConfig{
		BaseGCSFsConfig: sdk.BaseGCSFsConfig{
			KeyPrefix: keyPrefix,
		},
	}
	gcsfs, _ := vfs.NewGCSFs("", user.GetHomeDir(), "", gcsConfig)
	sftpconfig := vfs.SFTPFsConfig{
		BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
			Endpoint: sftpServerAddr,
			Username: defaultUsername,
			Prefix:   keyPrefix,
		},
		Password: kms.NewPlainSecret(defaultPassword),
	}
	sftpfs, _ := vfs.NewSFTPFs("", "", os.TempDir(), []string{user.Username}, sftpconfig)
	if runtime.GOOS != osWindows {
		filesystems = append(filesystems, s3fs, gcsfs, sftpfs)
	}
	rootPath := "/"
	for _, fs := range filesystems {
		path = filepath.Join(user.HomeDir, "/")
		rel = fs.GetRelativePath(path)
		assert.Equal(t, rootPath, rel)
		path = filepath.Join(user.HomeDir, "//")
		rel = fs.GetRelativePath(path)
		assert.Equal(t, rootPath, rel)
		path = filepath.Join(user.HomeDir, "../..")
		rel = fs.GetRelativePath(path)
		assert.Equal(t, rootPath, rel)
		path = filepath.Join(user.HomeDir, "../../../../../")
		rel = fs.GetRelativePath(path)
		assert.Equal(t, rootPath, rel)
		path = filepath.Join(user.HomeDir, "/..")
		rel = fs.GetRelativePath(path)
		assert.Equal(t, rootPath, rel)
		path = filepath.Join(user.HomeDir, "/../../../..")
		rel = fs.GetRelativePath(path)
		assert.Equal(t, rootPath, rel)
		path = filepath.Join(user.HomeDir, "")
		rel = fs.GetRelativePath(path)
		assert.Equal(t, rootPath, rel)
		path = filepath.Join(user.HomeDir, ".")
		rel = fs.GetRelativePath(path)
		assert.Equal(t, rootPath, rel)
		path = filepath.Join(user.HomeDir, "somedir")
		rel = fs.GetRelativePath(path)
		assert.Equal(t, "/somedir", rel)
		path = filepath.Join(user.HomeDir, "/somedir/subdir")
		rel = fs.GetRelativePath(path)
		assert.Equal(t, "/somedir/subdir", rel)
	}
}

func TestResolvePaths(t *testing.T) {
	user := getTestUser(true)
	var path, resolved string
	var err error
	filesystems := []vfs.Fs{vfs.NewOsFs("", user.GetHomeDir(), "")}
	keyPrefix := strings.TrimPrefix(user.GetHomeDir(), "/") + "/"
	s3config := vfs.S3FsConfig{
		BaseS3FsConfig: sdk.BaseS3FsConfig{
			KeyPrefix: keyPrefix,
			Bucket:    "bucket",
			Region:    "us-east-1",
		},
	}
	err = os.MkdirAll(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	s3fs, err := vfs.NewS3Fs("", user.GetHomeDir(), "", s3config)
	assert.NoError(t, err)
	gcsConfig := vfs.GCSFsConfig{
		BaseGCSFsConfig: sdk.BaseGCSFsConfig{
			KeyPrefix: keyPrefix,
		},
	}
	gcsfs, _ := vfs.NewGCSFs("", user.GetHomeDir(), "", gcsConfig)
	if runtime.GOOS != osWindows {
		filesystems = append(filesystems, s3fs, gcsfs)
	}
	for _, fs := range filesystems {
		path = "/"
		resolved, _ = fs.ResolvePath(filepath.ToSlash(path))
		assert.Equal(t, fs.Join(user.GetHomeDir(), "/"), resolved)
		path = "."
		resolved, _ = fs.ResolvePath(filepath.ToSlash(path))
		assert.Equal(t, fs.Join(user.GetHomeDir(), "/"), resolved)
		path = "test/sub"
		resolved, _ = fs.ResolvePath(filepath.ToSlash(path))
		assert.Equal(t, fs.Join(user.GetHomeDir(), "/test/sub"), resolved)
		path = "../test/sub"
		resolved, err = fs.ResolvePath(filepath.ToSlash(path))
		if vfs.IsLocalOsFs(fs) {
			assert.Error(t, err, "Unexpected resolved path: %v for: %v, fs: %v", resolved, path, fs.Name())
		} else {
			assert.Equal(t, fs.Join(user.GetHomeDir(), "/test/sub"), resolved)
		}
		path = "../../../test/../sub"
		resolved, err = fs.ResolvePath(filepath.ToSlash(path))
		if vfs.IsLocalOsFs(fs) {
			assert.Error(t, err, "Unexpected resolved path: %v for: %v, fs: %v", resolved, path, fs.Name())
		} else {
			assert.Equal(t, fs.Join(user.GetHomeDir(), "/sub"), resolved)
		}
	}
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestVirtualRelativePaths(t *testing.T) {
	user := getTestUser(true)
	mappedPath := filepath.Join(os.TempDir(), "mdir")
	vdirPath := "/vdir" //nolint:goconst
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	fsRoot := vfs.NewOsFs("", user.GetHomeDir(), "")
	fsVdir := vfs.NewOsFs("", mappedPath, vdirPath)
	rel := fsVdir.GetRelativePath(mappedPath)
	assert.Equal(t, vdirPath, rel)
	rel = fsRoot.GetRelativePath(filepath.Join(mappedPath, ".."))
	assert.Equal(t, "/", rel)
	// path outside home and virtual dir
	rel = fsRoot.GetRelativePath(filepath.Join(mappedPath, "../vdir1"))
	assert.Equal(t, "/", rel)
	rel = fsVdir.GetRelativePath(filepath.Join(mappedPath, "../vdir1"))
	assert.Equal(t, "/vdir", rel)
	rel = fsVdir.GetRelativePath(filepath.Join(mappedPath, "file.txt"))
	assert.Equal(t, "/vdir/file.txt", rel)
	rel = fsRoot.GetRelativePath(filepath.Join(user.HomeDir, "vdir1/file.txt"))
	assert.Equal(t, "/vdir1/file.txt", rel)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestUserPerms(t *testing.T) {
	user := getTestUser(true)
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermListItems}
	user.Permissions["/p"] = []string{dataprovider.PermDelete}
	user.Permissions["/p/1"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
	user.Permissions["/p/2"] = []string{dataprovider.PermCreateDirs}
	user.Permissions["/p/3"] = []string{dataprovider.PermChmod}
	user.Permissions["/p/3/4"] = []string{dataprovider.PermChtimes}
	user.Permissions["/tmp"] = []string{dataprovider.PermRename}
	assert.True(t, user.HasPerm(dataprovider.PermListItems, "/"))
	assert.True(t, user.HasPerm(dataprovider.PermListItems, "."))
	assert.True(t, user.HasPerm(dataprovider.PermListItems, ""))
	assert.True(t, user.HasPerm(dataprovider.PermListItems, "../"))
	// path p and /p are the same
	assert.True(t, user.HasPerm(dataprovider.PermDelete, "/p"))
	assert.True(t, user.HasPerm(dataprovider.PermDownload, "/p/1"))
	assert.True(t, user.HasPerm(dataprovider.PermCreateDirs, "p/2"))
	assert.True(t, user.HasPerm(dataprovider.PermChmod, "/p/3"))
	assert.True(t, user.HasPerm(dataprovider.PermChtimes, "p/3/4/"))
	assert.True(t, user.HasPerm(dataprovider.PermChtimes, "p/3/4/../4"))
	// undefined paths have permissions of the nearest path
	assert.True(t, user.HasPerm(dataprovider.PermListItems, "/p34"))
	assert.True(t, user.HasPerm(dataprovider.PermListItems, "/p34/p1/file.dat"))
	assert.True(t, user.HasPerm(dataprovider.PermChtimes, "/p/3/4/5/6"))
	assert.True(t, user.HasPerm(dataprovider.PermDownload, "/p/1/test/file.dat"))
}

func TestFilterFilePatterns(t *testing.T) {
	user := getTestUser(true)
	pattern := sdk.PatternsFilter{
		Path:            "/test",
		AllowedPatterns: []string{"*.jpg", "*.png"},
		DeniedPatterns:  []string{"*.pdf"},
	}
	filters := dataprovider.UserFilters{
		BaseUserFilters: sdk.BaseUserFilters{
			FilePatterns: []sdk.PatternsFilter{pattern},
		},
	}
	user.Filters = filters
	ok, _ := user.IsFileAllowed("/test/test.jPg")
	assert.True(t, ok)
	ok, _ = user.IsFileAllowed("/test/test.pdf")
	assert.False(t, ok)
	ok, _ = user.IsFileAllowed("/test.pDf")
	assert.True(t, ok)

	filters.FilePatterns = append(filters.FilePatterns, sdk.PatternsFilter{
		Path:            "/",
		AllowedPatterns: []string{"*.zip", "*.rar", "*.pdf"},
		DeniedPatterns:  []string{"*.gz"},
	})
	user.Filters = filters
	ok, _ = user.IsFileAllowed("/test1/test.gz")
	assert.False(t, ok)
	ok, _ = user.IsFileAllowed("/test1/test.zip")
	assert.True(t, ok)
	ok, _ = user.IsFileAllowed("/test/sub/test.pdf")
	assert.False(t, ok)
	ok, _ = user.IsFileAllowed("/test1/test.png")
	assert.False(t, ok)

	filters.FilePatterns = append(filters.FilePatterns, sdk.PatternsFilter{
		Path:           "/test/sub",
		DeniedPatterns: []string{"*.tar"},
	})
	user.Filters = filters
	ok, _ = user.IsFileAllowed("/test/sub/sub/test.tar")
	assert.False(t, ok)
	ok, _ = user.IsFileAllowed("/test/sub/test.gz")
	assert.True(t, ok)
	ok, _ = user.IsFileAllowed("/test/test.zip")
	assert.False(t, ok)
}

func TestUserAllowedLoginMethods(t *testing.T) {
	user := getTestUser(true)
	user.Filters.DeniedLoginMethods = dataprovider.ValidLoginMethods
	allowedMethods := user.GetAllowedLoginMethods()
	assert.Equal(t, 0, len(allowedMethods))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	allowedMethods = user.GetAllowedLoginMethods()
	assert.Equal(t, 4, len(allowedMethods))

	assert.True(t, util.IsStringInSlice(dataprovider.SSHLoginMethodKeyAndKeyboardInt, allowedMethods))
	assert.True(t, util.IsStringInSlice(dataprovider.SSHLoginMethodKeyAndPassword, allowedMethods))
}

func TestUserPartialAuth(t *testing.T) {
	user := getTestUser(true)
	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	assert.False(t, user.IsPartialAuth(dataprovider.LoginMethodPassword))
	assert.False(t, user.IsPartialAuth(dataprovider.SSHLoginMethodKeyboardInteractive))
	assert.True(t, user.IsPartialAuth(dataprovider.SSHLoginMethodPublicKey))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	assert.False(t, user.IsPartialAuth(dataprovider.SSHLoginMethodPublicKey))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
	}
	assert.False(t, user.IsPartialAuth(dataprovider.SSHLoginMethodPublicKey))
}

func TestUserGetNextAuthMethods(t *testing.T) {
	user := getTestUser(true)
	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	methods := user.GetNextAuthMethods(nil, true)
	assert.Equal(t, 0, len(methods))

	methods = user.GetNextAuthMethods([]string{dataprovider.LoginMethodPassword}, true)
	assert.Equal(t, 0, len(methods))

	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodKeyboardInteractive}, true)
	assert.Equal(t, 0, len(methods))

	methods = user.GetNextAuthMethods([]string{
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}, true)
	assert.Equal(t, 0, len(methods))

	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPublicKey}, true)
	assert.Equal(t, 2, len(methods))
	assert.True(t, util.IsStringInSlice(dataprovider.LoginMethodPassword, methods))
	assert.True(t, util.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, methods))
	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPublicKey}, false)
	assert.Equal(t, 1, len(methods))
	assert.True(t, util.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, methods))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
		dataprovider.SSHLoginMethodKeyAndKeyboardInt,
	}
	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPublicKey}, true)
	assert.Equal(t, 1, len(methods))
	assert.True(t, util.IsStringInSlice(dataprovider.LoginMethodPassword, methods))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
		dataprovider.SSHLoginMethodKeyAndPassword,
	}
	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPublicKey}, true)
	assert.Equal(t, 1, len(methods))
	assert.True(t, util.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, methods))
}

func TestUserIsLoginMethodAllowed(t *testing.T) {
	user := getTestUser(true)
	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	assert.False(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolSSH, nil))
	assert.False(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolFTP, nil))
	assert.False(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolWebDAV, nil))
	assert.False(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodPublicKey, common.ProtocolSSH, nil))
	assert.False(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodKeyboardInteractive, common.ProtocolSSH, nil))
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolSSH,
		[]string{dataprovider.SSHLoginMethodPublicKey}))
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodKeyboardInteractive, common.ProtocolSSH,
		[]string{dataprovider.SSHLoginMethodPublicKey}))
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodKeyAndPassword, common.ProtocolSSH,
		[]string{dataprovider.SSHLoginMethodPublicKey}))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolSSH, nil))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.SSHLoginMethodPassword,
	}
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolHTTP, nil))
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolFTP, nil))
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolWebDAV, nil))
	assert.False(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, common.ProtocolSSH, nil))
}

func TestUserEmptySubDirPerms(t *testing.T) {
	user := getTestUser(true)
	user.Permissions = make(map[string][]string)
	user.Permissions["/emptyperms"] = []string{}
	for _, p := range dataprovider.ValidPerms {
		assert.False(t, user.HasPerm(p, "/emptyperms"))
	}
}

func TestUserFiltersIPMaskConditions(t *testing.T) {
	user := getTestUser(true)
	// with no filter login must be allowed even if the remoteIP is invalid
	assert.True(t, user.IsLoginFromAddrAllowed("192.168.1.5"))
	assert.True(t, user.IsLoginFromAddrAllowed("invalid"))

	user.Filters.DeniedIP = append(user.Filters.DeniedIP, "192.168.1.0/24")
	assert.False(t, user.IsLoginFromAddrAllowed("192.168.1.5"))
	assert.True(t, user.IsLoginFromAddrAllowed("192.168.2.6"))

	user.Filters.AllowedIP = append(user.Filters.AllowedIP, "192.168.1.5/32")
	// if the same ip/mask is both denied and allowed then login must be denied
	assert.False(t, user.IsLoginFromAddrAllowed("192.168.1.5"))
	assert.False(t, user.IsLoginFromAddrAllowed("192.168.3.6"))

	user.Filters.DeniedIP = []string{}
	assert.True(t, user.IsLoginFromAddrAllowed("192.168.1.5"))
	assert.False(t, user.IsLoginFromAddrAllowed("192.168.1.6"))

	user.Filters.DeniedIP = []string{"192.168.0.0/16", "172.16.0.0/16"}
	user.Filters.AllowedIP = []string{}
	assert.False(t, user.IsLoginFromAddrAllowed("192.168.5.255"))
	assert.False(t, user.IsLoginFromAddrAllowed("172.16.1.2"))
	assert.True(t, user.IsLoginFromAddrAllowed("172.18.2.1"))

	user.Filters.AllowedIP = []string{"10.4.4.0/24"}
	assert.False(t, user.IsLoginFromAddrAllowed("10.5.4.2"))
	assert.True(t, user.IsLoginFromAddrAllowed("10.4.4.2"))
	assert.True(t, user.IsLoginFromAddrAllowed("invalid"))
}

func TestGetVirtualFolderForPath(t *testing.T) {
	user := getTestUser(true)
	mappedPath1 := filepath.Join(os.TempDir(), "vpath1")
	mappedPath2 := filepath.Join(os.TempDir(), "vpath1")
	mappedPath3 := filepath.Join(os.TempDir(), "vpath3")
	vdirPath := "/vdir/sub"
	vSubDirPath := path.Join(vdirPath, "subdir", "subdir")
	vSubDir1Path := path.Join(vSubDirPath, "subdir", "subdir")
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath,
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: vSubDir1Path,
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath3,
		},
		VirtualPath: vSubDirPath,
	})
	folder, err := user.GetVirtualFolderForPath(path.Join(vSubDirPath, "file"))
	assert.NoError(t, err)
	assert.Equal(t, folder.MappedPath, mappedPath3)
	_, err = user.GetVirtualFolderForPath("/file")
	assert.Error(t, err)
	folder, err = user.GetVirtualFolderForPath(path.Join(vdirPath, "/file"))
	assert.NoError(t, err)
	assert.Equal(t, folder.MappedPath, mappedPath1)
	folder, err = user.GetVirtualFolderForPath(path.Join(vSubDirPath+"1", "file"))
	assert.NoError(t, err)
	assert.Equal(t, folder.MappedPath, mappedPath1)
	_, err = user.GetVirtualFolderForPath("/vdir/sub1/file")
	assert.Error(t, err)
	folder, err = user.GetVirtualFolderForPath(vdirPath)
	assert.NoError(t, err)
}

func TestStatVFS(t *testing.T) {
	usePubKey := false
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	testFileSize := int64(65535)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		stat, err := client.StatVFS("/")
		assert.NoError(t, err)
		assert.Greater(t, stat.ID, uint32(0))
		assert.Greater(t, stat.Blocks, uint64(0))
		assert.Greater(t, stat.Bsize, uint64(0))

		_, err = client.StatVFS("missing-path")
		assert.Error(t, err)
		assert.True(t, os.IsNotExist(err))
	}
	user.QuotaFiles = 100
	user.Filters.DisableFsChecks = true
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)

		stat, err := client.StatVFS("/")
		assert.NoError(t, err)
		assert.Greater(t, stat.ID, uint32(0))
		assert.Greater(t, stat.Blocks, uint64(0))
		assert.Greater(t, stat.Bsize, uint64(0))
		assert.Equal(t, uint64(100), stat.Files)
		assert.Equal(t, uint64(99), stat.Ffree)
	}

	user.QuotaSize = 8192
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		stat, err := client.StatVFS("/")
		assert.NoError(t, err)
		assert.Greater(t, stat.ID, uint32(0))
		assert.Greater(t, stat.Blocks, uint64(0))
		assert.Greater(t, stat.Bsize, uint64(0))
		assert.Equal(t, uint64(100), stat.Files)
		assert.Equal(t, uint64(0), stat.Ffree)
		assert.Equal(t, uint64(2), stat.Blocks)
		assert.Equal(t, uint64(0), stat.Bfree)
	}
	user.QuotaFiles = 0
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		stat, err := client.StatVFS("/")
		assert.NoError(t, err)
		assert.Greater(t, stat.ID, uint32(0))
		assert.Greater(t, stat.Blocks, uint64(0))
		assert.Greater(t, stat.Bsize, uint64(0))
		assert.Greater(t, stat.Files, uint64(0))
		assert.Equal(t, uint64(0), stat.Ffree)
		assert.Equal(t, uint64(2), stat.Blocks)
		assert.Equal(t, uint64(0), stat.Bfree)
	}

	user.QuotaSize = 1
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		stat, err := client.StatVFS("/")
		assert.NoError(t, err)
		assert.Greater(t, stat.ID, uint32(0))
		assert.Equal(t, uint64(1), stat.Blocks)
		assert.Equal(t, uint64(1), stat.Bsize)
		assert.Greater(t, stat.Files, uint64(0))
		assert.Equal(t, uint64(0), stat.Ffree)
		assert.Equal(t, uint64(1), stat.Blocks)
		assert.Equal(t, uint64(0), stat.Bfree)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestStatVFSCloudBackend(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	u.FsConfig.AzBlobConfig.SASURL = kms.NewPlainSecret("https://myaccount.blob.core.windows.net/sasurl")
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()

		err = dataprovider.UpdateUserQuota(&user, 100, 8192, true)
		assert.NoError(t, err)
		stat, err := client.StatVFS("/")
		assert.NoError(t, err)
		assert.Greater(t, stat.ID, uint32(0))
		assert.Greater(t, stat.Blocks, uint64(0))
		assert.Greater(t, stat.Bsize, uint64(0))
		assert.Equal(t, uint64(1000000+100), stat.Files)
		assert.Equal(t, uint64(2147483648+2), stat.Blocks)
		assert.Equal(t, uint64(1000000), stat.Ffree)
		assert.Equal(t, uint64(2147483648), stat.Bfree)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSSHCommands(t *testing.T) {
	usePubKey := false
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	_, err = runSSHCommand("ls", user, usePubKey)
	assert.Error(t, err, "unsupported ssh command must fail")

	_, err = runSSHCommand("cd", user, usePubKey)
	assert.NoError(t, err)
	out, err := runSSHCommand("pwd", user, usePubKey)
	if assert.NoError(t, err) {
		assert.Equal(t, "/\n", string(out))
	}
	out, err = runSSHCommand("md5sum", user, usePubKey)
	assert.NoError(t, err)
	// echo -n '' | md5sum
	assert.Contains(t, string(out), "d41d8cd98f00b204e9800998ecf8427e")

	out, err = runSSHCommand("sha1sum", user, usePubKey)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "da39a3ee5e6b4b0d3255bfef95601890afd80709")

	out, err = runSSHCommand("sha256sum", user, usePubKey)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	out, err = runSSHCommand("sha384sum", user, usePubKey)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSSHFileHash(t *testing.T) {
	usePubKey := true
	localUser, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	u := getTestUserWithCryptFs(usePubKey)
	u.Username = u.Username + "_crypt"
	cryptUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser, cryptUser} {
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			testFilePath := filepath.Join(homeBasePath, testFileName)
			testFileSize := int64(65535)
			err = createTestFile(testFilePath, testFileSize)
			assert.NoError(t, err)
			err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
			assert.NoError(t, err)
			user.Permissions = make(map[string][]string)
			user.Permissions["/"] = []string{dataprovider.PermUpload}
			_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
			assert.NoError(t, err)
			_, err = runSSHCommand("sha512sum "+testFileName, user, usePubKey)
			assert.Error(t, err, "hash command with no list permission must fail")

			user.Permissions["/"] = []string{dataprovider.PermAny}
			_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
			assert.NoError(t, err)

			initialHash, err := computeHashForFile(sha512.New(), testFilePath)
			assert.NoError(t, err)

			out, err := runSSHCommand("sha512sum "+testFileName, user, usePubKey)
			if assert.NoError(t, err) {
				assert.Contains(t, string(out), initialHash)
			}
			_, err = runSSHCommand("sha512sum invalid_path", user, usePubKey)
			assert.Error(t, err, "hash for an invalid path must fail")

			err = os.Remove(testFilePath)
			assert.NoError(t, err)
		}
	}
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(cryptUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestSSHCopy(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1/subdir"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2/subdir"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  100,
		QuotaSize:   0,
	})
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:           "/",
			DeniedPatterns: []string{"*.denied"},
		},
	}
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testDir := "adir"
	testDir1 := "adir1"
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileSize := int64(131072)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileName1 := "test_file1.dat"
		testFileSize1 := int64(65537)
		testFilePath1 := filepath.Join(homeBasePath, testFileName1)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = createTestFile(testFilePath1, testFileSize1)
		assert.NoError(t, err)
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, testDir1))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, testDir1))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(testDir, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(testDir, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testDir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath1, testDir1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testDir1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath2, testDir1, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = client.Symlink(path.Join(testDir, testFileName), testFileName)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 4, user.UsedQuotaFiles)
		assert.Equal(t, 2*testFileSize+2*testFileSize1, user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
		assert.Equal(t, 2, f.UsedQuotaFiles)

		_, err = client.Stat(testDir1)
		assert.Error(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v", path.Join(vdirPath1, testDir1)), user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand("sftpgo-copy", user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", testFileName, testFileName+".linkcopy"), user, usePubKey)
		assert.Error(t, err)
		out, err := runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath1, testDir1), "."), user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
			fi, err := client.Stat(testDir1)
			if assert.NoError(t, err) {
				assert.True(t, fi.IsDir())
			}
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 6, user.UsedQuotaFiles)
			assert.Equal(t, 3*testFileSize+3*testFileSize1, user.UsedQuotaSize)
		}
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", "missing\\ dir", "."), user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath1, testDir1), "."), user, usePubKey)
		assert.Error(t, err)
		out, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath2, testDir1, testFileName), testFileName+".copy"),
			user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
			fi, err := client.Stat(testFileName + ".copy")
			if assert.NoError(t, err) {
				assert.True(t, fi.Mode().IsRegular())
			}
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 7, user.UsedQuotaFiles)
			assert.Equal(t, 4*testFileSize+3*testFileSize1, user.UsedQuotaSize)
		}
		out, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath1, testDir1), path.Join(vdirPath2, testDir1+"copy")),
			user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
			fi, err := client.Stat(path.Join(vdirPath2, testDir1+"copy"))
			if assert.NoError(t, err) {
				assert.True(t, fi.IsDir())
			}
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 7, user.UsedQuotaFiles)
			assert.Equal(t, 4*testFileSize+3*testFileSize1, user.UsedQuotaSize)
			f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, testFileSize*2+testFileSize1*2, f.UsedQuotaSize)
			assert.Equal(t, 4, f.UsedQuotaFiles)
		}
		out, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath1, testDir1), path.Join(vdirPath1, testDir1+"copy")),
			user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
			_, err := client.Stat(path.Join(vdirPath2, testDir1+"copy"))
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 9, user.UsedQuotaFiles)
			assert.Equal(t, 5*testFileSize+4*testFileSize1, user.UsedQuotaSize)
			f, _, err = httpdtest.GetFolderByName(folderName1, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 2*testFileSize+2*testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 4, f.UsedQuotaFiles)
		}

		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath2, ".."), "newdir"), user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(testDir, testFileName), testFileName+".denied"), user, usePubKey)
		assert.Error(t, err)
		if runtime.GOOS != osWindows {
			subPath := filepath.Join(mappedPath1, testDir1, "asubdir", "anothersub", "another")
			err = os.MkdirAll(subPath, os.ModePerm)
			assert.NoError(t, err)
			err = os.Chmod(subPath, 0001)
			assert.NoError(t, err)
			// c.connection.fs.GetDirSize(fsSourcePath) will fail scanning subdirs
			// checkRecursiveCopyPermissions will work since it will skip subdirs with no permissions
			_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", vdirPath1, "newdir"), user, usePubKey)
			assert.Error(t, err)
			err = os.Chmod(subPath, os.ModePerm)
			assert.NoError(t, err)
			err = os.Chmod(filepath.Join(user.GetHomeDir(), testDir1), 0555)
			assert.NoError(t, err)
			_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath1, testDir1, testFileName),
				path.Join(testDir1, "anewdir")), user, usePubKey)
			assert.Error(t, err)
			err = os.Chmod(filepath.Join(user.GetHomeDir(), testDir1), os.ModePerm)
			assert.NoError(t, err)

			err = os.RemoveAll(filepath.Join(user.GetHomeDir(), "vdir1"))
			assert.NoError(t, err)
			err = os.Chmod(user.GetHomeDir(), 0555)
			assert.NoError(t, err)
			_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath2), "/vdir1"), user, usePubKey)
			assert.Error(t, err)
			err = os.Chmod(user.GetHomeDir(), os.ModePerm)
			assert.NoError(t, err)
		}

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestSSHCopyPermissions(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Permissions["/dir1"] = []string{dataprovider.PermUpload, dataprovider.PermDownload, dataprovider.PermListItems}
	u.Permissions["/dir2"] = []string{dataprovider.PermCreateDirs, dataprovider.PermUpload, dataprovider.PermDownload,
		dataprovider.PermListItems}
	u.Permissions["/dir3"] = []string{dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermDownload,
		dataprovider.PermListItems}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testDir := "tDir"
		testFileSize := int64(131072)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join("/", testDir, testFileName), testFileSize, client)
		assert.NoError(t, err)
		// test copy file with no permission
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join("/", testDir, testFileName), path.Join("/dir3", testFileName)),
			user, usePubKey)
		assert.Error(t, err)
		// test copy dir with no create dirs perm
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join("/", testDir), "/dir1/"), user, usePubKey)
		assert.Error(t, err)
		// dir2 has the needed permissions
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join("/", testDir), "/dir2/"), user, usePubKey)
		assert.NoError(t, err)
		info, err := client.Stat(path.Join("/dir2", testDir))
		if assert.NoError(t, err) {
			assert.True(t, info.IsDir())
		}
		info, err = client.Stat(path.Join("/dir2", testDir, testFileName))
		if assert.NoError(t, err) {
			assert.True(t, info.Mode().IsRegular())
		}
		// now create a symlink, dir2 has no create symlink permission
		err = client.Symlink(path.Join("/", testDir, testFileName), path.Join("/", testDir, testFileName+".link"))
		assert.NoError(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join("/", testDir), "/dir2/sub"), user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join("/", testDir), "/newdir"), user, usePubKey)
		assert.NoError(t, err)
		// now delete the file and copy inside /dir3
		err = client.Remove(path.Join("/", testDir, testFileName))
		assert.NoError(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join("/", testDir), "/dir3"), user, usePubKey)
		assert.NoError(t, err)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSSHCopyQuotaLimits(t *testing.T) {
	usePubKey := true
	testFileSize := int64(131072)
	testFileSize1 := int64(65536)
	testFileSize2 := int64(32768)
	u := getTestUser(usePubKey)
	u.QuotaFiles = 3
	u.QuotaSize = testFileSize + testFileSize1 + 1
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  3,
		QuotaSize:   testFileSize + testFileSize1 + 1,
	})
	u.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:           "/",
			DeniedPatterns: []string{"*.denied"},
		},
	}
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testDir := "testDir"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileName1 := "test_file1.dat"
		testFilePath1 := filepath.Join(homeBasePath, testFileName1)
		testFileName2 := "test_file2.dat"
		testFilePath2 := filepath.Join(homeBasePath, testFileName2)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = createTestFile(testFilePath1, testFileSize1)
		assert.NoError(t, err)
		err = createTestFile(testFilePath2, testFileSize2)
		assert.NoError(t, err)
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, testDir))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath2, path.Join(testDir, testFileName2), testFileSize2, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath2, path.Join(testDir, testFileName2+".dupl"), testFileSize2, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath2, path.Join(vdirPath2, testDir, testFileName2), testFileSize2, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath2, path.Join(vdirPath2, testDir, testFileName2+".dupl"), testFileSize2, client)
		assert.NoError(t, err)
		// user quota: 2 files, size: 32768*2, folder2 quota: 2 files, size: 32768*2
		// try to duplicate testDir, this will result in 4 file (over quota) and 32768*4 bytes (not over quota)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", testDir, testDir+"_copy"), user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath2, testDir),
			path.Join(vdirPath2, testDir+"_copy")), user, usePubKey)
		assert.Error(t, err)

		_, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", testDir), user, usePubKey)
		assert.NoError(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", path.Join(vdirPath2, testDir)), user, usePubKey)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 0, user.UsedQuotaFiles)
		assert.Equal(t, int64(0), user.UsedQuotaSize)
		f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 0, f.UsedQuotaFiles)
		assert.Equal(t, int64(0), f.UsedQuotaSize)
		err = client.Mkdir(path.Join(vdirPath1, testDir))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, testDir))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testDir, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath1, testDir, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testDir, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath2, testDir, testFileName1), testFileSize1, client)
		assert.NoError(t, err)

		// vdir1 is included in user quota, file limit will be exceeded
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath1, testDir), "/"), user, usePubKey)
		assert.Error(t, err)

		// vdir2 size limit will be exceeded
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath1, testDir, testFileName),
			vdirPath2+"/"), user, usePubKey)
		assert.Error(t, err)
		// now decrease the limits
		user.QuotaFiles = 1
		user.QuotaSize = testFileSize * 10
		user.VirtualFolders[1].QuotaSize = testFileSize
		user.VirtualFolders[1].QuotaFiles = 10
		user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		assert.Equal(t, 1, user.QuotaFiles)
		assert.Equal(t, testFileSize*10, user.QuotaSize)
		if assert.Len(t, user.VirtualFolders, 2) {
			f := user.VirtualFolders[1]
			assert.Equal(t, testFileSize, f.QuotaSize)
			assert.Equal(t, 10, f.QuotaFiles)
		}
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath1, testDir),
			path.Join(vdirPath2, testDir+".copy")), user, usePubKey)
		assert.Error(t, err)

		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath2, testDir),
			testDir+".copy"), user, usePubKey)
		assert.Error(t, err)

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
		err = os.Remove(testFilePath2)
		assert.NoError(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestSSHCopyRemoveNonLocalFs(t *testing.T) {
	usePubKey := true
	localUser, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(sftpUser, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testDir := "test"
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", testDir, testDir+"_copy"), sftpUser, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", testDir), sftpUser, usePubKey)
		assert.Error(t, err)
	}

	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestSSHRemove(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1/sub"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2/sub"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  100,
		QuotaSize:   0,
	})
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testFileSize := int64(131072)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileName1 := "test_file1.dat"
		testFileSize1 := int64(65537)
		testFilePath1 := filepath.Join(homeBasePath, testFileName1)
		testDir := "testdir"
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = createTestFile(testFilePath1, testFileSize1)
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, testDir))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, testDir))
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testDir, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath1, testDir, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testDir, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, path.Join(vdirPath2, testDir, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", testFileName+".link"), user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand("sftpgo-remove /vdir1", user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand("sftpgo-remove /", user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand("sftpgo-remove", user, usePubKey)
		assert.Error(t, err)
		out, err := runSSHCommand(fmt.Sprintf("sftpgo-remove %v", testFileName), user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
			_, err := client.Stat(testFileName)
			assert.Error(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 3, user.UsedQuotaFiles)
			assert.Equal(t, testFileSize+2*testFileSize1, user.UsedQuotaSize)
		}
		out, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", path.Join(vdirPath1, testDir)), user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
			_, err := client.Stat(path.Join(vdirPath1, testFileName))
			assert.Error(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 1, user.UsedQuotaFiles)
			assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		}
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", vdirPath1), user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand("sftpgo-remove /", user, usePubKey)
		assert.Error(t, err)
		_, err = runSSHCommand("sftpgo-remove missing_file", user, usePubKey)
		assert.Error(t, err)
		if runtime.GOOS != osWindows {
			err = os.Chmod(filepath.Join(mappedPath2, testDir), 0555)
			assert.NoError(t, err)
			_, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", path.Join(vdirPath2, testDir)), user, usePubKey)
			assert.Error(t, err)
			err = os.Chmod(filepath.Join(mappedPath2, testDir), 0001)
			assert.NoError(t, err)
			_, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", path.Join(vdirPath2, testDir)), user, usePubKey)
			assert.Error(t, err)
			err = os.Chmod(filepath.Join(mappedPath2, testDir), os.ModePerm)
			assert.NoError(t, err)
		}
	}

	// test remove dir with no delete perm
	user.Permissions["/"] = []string{dataprovider.PermUpload, dataprovider.PermDownload, dataprovider.PermListItems}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	conn, client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		_, err = runSSHCommand("sftpgo-remove adir", user, usePubKey)
		assert.Error(t, err)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestSSHRemoveCryptFs(t *testing.T) {
	usePubKey := false
	u := getTestUserWithCryptFs(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1/sub"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2/sub"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
			FsConfig: vfs.Filesystem{
				Provider: sdk.CryptedFilesystemProvider,
				CryptConfig: vfs.CryptFsConfig{
					Passphrase: kms.NewPlainSecret(defaultPassword),
				},
			},
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  100,
		QuotaSize:   0,
	})
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		testDir := "tdir"
		err = client.Mkdir(testDir)
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath1, testDir))
		assert.NoError(t, err)
		err = client.Mkdir(path.Join(vdirPath2, testDir))
		assert.NoError(t, err)
		testFileSize := int64(32768)
		testFileSize1 := int64(65536)
		testFileName1 := "test_file1.dat"
		err = writeSFTPFile(testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(testDir, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(testDir, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, testDir, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath1, testDir, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, testDir, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = writeSFTPFile(path.Join(vdirPath2, testDir, testFileName1), testFileSize1, client)
		assert.NoError(t, err)
		_, err = runSSHCommand("sftpgo-remove /vdir2", user, usePubKey)
		assert.Error(t, err)
		out, err := runSSHCommand(fmt.Sprintf("sftpgo-remove %v", testFileName), user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
			_, err := client.Stat(testFileName)
			assert.Error(t, err)
		}
		out, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", testDir), user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
		}
		out, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", path.Join(vdirPath1, testDir)), user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
		}
		out, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", path.Join(vdirPath2, testDir, testFileName)), user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
		}
		err = writeSFTPFile(path.Join(vdirPath2, testDir, testFileName), testFileSize, client)
		assert.NoError(t, err)
		out, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", path.Join(vdirPath2, testDir)), user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
		}
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Greater(t, user.UsedQuotaSize, testFileSize1)
	}

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestBasicGitCommands(t *testing.T) {
	if len(gitPath) == 0 || len(sshPath) == 0 || runtime.GOOS == osWindows {
		t.Skip("git and/or ssh command not found or OS is windows, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	repoName := "testrepo" //nolint:goconst
	clonePath := filepath.Join(homeBasePath, repoName)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(filepath.Join(homeBasePath, repoName))
	assert.NoError(t, err)
	out, err := initGitRepo(filepath.Join(user.HomeDir, repoName))
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	out, err = cloneGitRepo(homeBasePath, "/"+repoName, user.Username)
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	out, err = addFileToGitRepo(clonePath, 128)
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	user.QuotaFiles = 100000
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	out, err = pushToGitRepo(clonePath)
	if !assert.NoError(t, err, "unexpected error, out: %v", string(out)) {
		printLatestLogs(10)
	}

	out, err = addFileToGitRepo(clonePath, 131072)
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	user.QuotaSize = user.UsedQuotaSize + 1
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	out, err = pushToGitRepo(clonePath)
	assert.Error(t, err, "git push must fail if quota is exceeded, out: %v", string(out))

	aDir := filepath.Join(user.GetHomeDir(), repoName, "adir")
	err = os.MkdirAll(aDir, 0001)
	assert.NoError(t, err)
	_, err = pushToGitRepo(clonePath)
	assert.Error(t, err)
	err = os.Chmod(aDir, os.ModePerm)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(clonePath)
	assert.NoError(t, err)
}

func TestGitQuotaVirtualFolders(t *testing.T) {
	if len(gitPath) == 0 || len(sshPath) == 0 || runtime.GOOS == osWindows {
		t.Skip("git and/or ssh command not found or OS is windows, unable to execute this test")
	}
	usePubKey := true
	repoName := "testrepo"
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1
	u.QuotaSize = 131072
	mappedPath := filepath.Join(os.TempDir(), "repo")
	folderName := filepath.Base(mappedPath)
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: "/" + repoName,
		QuotaFiles:  0,
		QuotaSize:   0,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		// we upload a file so the user is over quota
		defer conn.Close()
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, u.QuotaSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, u.QuotaSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}

	clonePath := filepath.Join(homeBasePath, repoName)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(filepath.Join(homeBasePath, repoName))
	assert.NoError(t, err)
	out, err := initGitRepo(mappedPath)
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	out, err = cloneGitRepo(homeBasePath, "/"+repoName, user.Username)
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	out, err = addFileToGitRepo(clonePath, 128)
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	out, err = pushToGitRepo(clonePath)
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
	err = os.RemoveAll(clonePath)
	assert.NoError(t, err)
}

func TestGitErrors(t *testing.T) {
	if len(gitPath) == 0 || len(sshPath) == 0 || runtime.GOOS == osWindows {
		t.Skip("git and/or ssh command not found or OS is windows, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	repoName := "testrepo"
	clonePath := filepath.Join(homeBasePath, repoName)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(filepath.Join(homeBasePath, repoName))
	assert.NoError(t, err)
	out, err := cloneGitRepo(homeBasePath, "/"+repoName, user.Username)
	assert.Error(t, err, "cloning a missing repo must fail, out: %v", string(out))

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(clonePath)
	assert.NoError(t, err)
}

// Start SCP tests
func TestSCPBasicHandling(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaSize = 6553600
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	u.QuotaSize = 6553600
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(131074)
	expectedQuotaSize := testFileSize
	expectedQuotaFiles := 1
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
		remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
		localPath := filepath.Join(homeBasePath, "scp_download.dat")
		// test to download a missing file
		err = scpDownload(localPath, remoteDownPath, false, false)
		assert.Error(t, err, "downloading a missing file via scp must fail")
		err = scpUpload(testFilePath, remoteUpPath, false, false)
		assert.NoError(t, err)
		err = scpDownload(localPath, remoteDownPath, false, false)
		assert.NoError(t, err)
		fi, err := os.Stat(localPath)
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize, fi.Size())
		}
		err = os.Remove(localPath)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
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
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
}

func TestSCPUploadFileOverwrite(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	localUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	u = getTestSFTPUser(usePubKey)
	u.QuotaFiles = 1000
	sftpUser, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(32760)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
		err = scpUpload(testFilePath, remoteUpPath, true, false)
		assert.NoError(t, err)
		// test a new upload that must overwrite the existing file
		err = scpUpload(testFilePath, remoteUpPath, true, false)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		assert.Equal(t, 1, user.UsedQuotaFiles)

		remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
		localPath := filepath.Join(homeBasePath, "scp_download.dat")
		err = scpDownload(localPath, remoteDownPath, false, false)
		assert.NoError(t, err)

		fi, err := os.Stat(localPath)
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize, fi.Size())
		}
		// now create a simlink via SFTP, replace the symlink with a file via SCP and check quota usage
		conn, client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
			defer conn.Close()
			defer client.Close()
			err = client.Symlink(testFileName, testFileName+".link")
			assert.NoError(t, err)
			user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, testFileSize, user.UsedQuotaSize)
			assert.Equal(t, 1, user.UsedQuotaFiles)
		}
		err = scpUpload(testFilePath, remoteUpPath+".link", true, false)
		assert.NoError(t, err)
		user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize*2, user.UsedQuotaSize)
		assert.Equal(t, 2, user.UsedQuotaFiles)

		err = os.Remove(localPath)
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
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPRecursive(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	localUser, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	sftpUser, _, err := httpdtest.AddUser(getTestSFTPUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	testBaseDirName := "test_dir"
	testBaseDirPath := filepath.Join(homeBasePath, testBaseDirName)
	testBaseDirDownName := "test_dir_down" //nolint:goconst
	testBaseDirDownPath := filepath.Join(homeBasePath, testBaseDirDownName)
	testFilePath := filepath.Join(homeBasePath, testBaseDirName, testFileName)
	testFilePath1 := filepath.Join(homeBasePath, testBaseDirName, testBaseDirName, testFileName)
	testFileSize := int64(131074)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = createTestFile(testFilePath1, testFileSize)
	assert.NoError(t, err)
	for _, user := range []dataprovider.User{localUser, sftpUser} {
		remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testBaseDirName))
		// test to download a missing dir
		err = scpDownload(testBaseDirDownPath, remoteDownPath, true, true)
		assert.Error(t, err, "downloading a missing dir via scp must fail")

		remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
		err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
		assert.NoError(t, err)
		// overwrite existing dir
		err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
		assert.NoError(t, err)
		err = scpDownload(testBaseDirDownPath, remoteDownPath, true, true)
		assert.NoError(t, err)
		// test download without passing -r
		err = scpDownload(testBaseDirDownPath, remoteDownPath, true, false)
		assert.Error(t, err, "recursive download without -r must fail")

		fi, err := os.Stat(filepath.Join(testBaseDirDownPath, testFileName))
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize, fi.Size())
		}
		fi, err = os.Stat(filepath.Join(testBaseDirDownPath, testBaseDirName, testFileName))
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize, fi.Size())
		}
		// upload to a non existent dir
		remoteUpPath = fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/non_existent_dir")
		err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
		assert.Error(t, err, "uploading via scp to a non existent dir must fail")

		err = os.RemoveAll(testBaseDirDownPath)
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

	err = os.RemoveAll(testBaseDirPath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(sftpUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(localUser.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(localUser, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPStartDirectory(t *testing.T) {
	usePubKey := true
	startDir := "/sta rt/dir"
	u := getTestUser(usePubKey)
	u.Filters.StartDirectory = startDir
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)

	testFileSize := int64(131072)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:", user.Username)
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.NoError(t, err)
	err = scpDownload(localPath, remoteDownPath, false, false)
	assert.NoError(t, err)
	// check that the file is in the start directory
	_, err = os.Stat(filepath.Join(user.HomeDir, startDir, testFileName))
	assert.NoError(t, err)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localPath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSCPPatternsFilter(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFileSize := int64(131072)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.NoError(t, err)
	user.Filters.FilePatterns = []sdk.PatternsFilter{
		{
			Path:            "/",
			AllowedPatterns: []string{"*.zip"},
			DeniedPatterns:  []string{},
		},
	}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	err = scpDownload(localPath, remoteDownPath, false, false)
	assert.Error(t, err, "scp download must fail")
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.Error(t, err, "scp upload must fail")

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = os.Stat(localPath)
	if err == nil {
		err = os.Remove(localPath)
		assert.NoError(t, err)
	}
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSCPTransferQuotaLimits(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.DownloadDataTransfer = 1
	u.UploadDataTransfer = 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(550000)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)

	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.NoError(t, err)
	err = scpDownload(localDownloadPath, remoteDownPath, false, false)
	assert.NoError(t, err)
	// error while download is active
	err = scpDownload(localDownloadPath, remoteDownPath, false, false)
	assert.Error(t, err)
	// error before starting the download
	err = scpDownload(localDownloadPath, remoteDownPath, false, false)
	assert.Error(t, err)
	// error while upload is active
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.Error(t, err)
	// error before starting the upload
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.Error(t, err)

	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Greater(t, user.UsedDownloadDataTransfer, int64(1024*1024))
	assert.Greater(t, user.UsedUploadDataTransfer, int64(1024*1024))

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSCPUploadMaxSize(t *testing.T) {
	testFileSize := int64(65535)
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Filters.MaxUploadFileSize = testFileSize + 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	testFileSize1 := int64(131072)
	testFileName1 := "test_file1.dat"
	testFilePath1 := filepath.Join(homeBasePath, testFileName1)
	err = createTestFile(testFilePath1, testFileSize1)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	err = scpUpload(testFilePath1, remoteUpPath, false, false)
	assert.Error(t, err)
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSCPVirtualFolders(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	folderName := filepath.Base(mappedPath)
	vdirPath := "/vdir"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName,
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testBaseDirName := "test_dir"
	testBaseDirPath := filepath.Join(homeBasePath, testBaseDirName)
	testBaseDirDownName := "test_dir_down"
	testBaseDirDownPath := filepath.Join(homeBasePath, testBaseDirDownName)
	testFilePath := filepath.Join(homeBasePath, testBaseDirName, testFileName)
	testFilePath1 := filepath.Join(homeBasePath, testBaseDirName, testBaseDirName, testFileName)
	testFileSize := int64(131074)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = createTestFile(testFilePath1, testFileSize)
	assert.NoError(t, err)
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, vdirPath)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, vdirPath)
	err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
	assert.NoError(t, err)
	err = scpDownload(testBaseDirDownPath, remoteDownPath, true, true)
	assert.NoError(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(testBaseDirPath)
	assert.NoError(t, err)
	err = os.RemoveAll(testBaseDirDownPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestSCPNestedFolders(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	baseUser, resp, err := httpdtest.AddUser(getTestUser(false), http.StatusCreated)
	assert.NoError(t, err, string(resp))
	usePubKey := true
	u := getTestUser(usePubKey)
	u.HomeDir += "_folders"
	u.Username += "_folders"
	mappedPathSFTP := filepath.Join(os.TempDir(), "sftp")
	folderNameSFTP := filepath.Base(mappedPathSFTP)
	vdirSFTPPath := "/vdir/sftp"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderNameSFTP,
			FsConfig: vfs.Filesystem{
				Provider: sdk.SFTPFilesystemProvider,
				SFTPConfig: vfs.SFTPFsConfig{
					BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
						Endpoint: sftpServerAddr,
						Username: baseUser.Username,
					},
					Password: kms.NewPlainSecret(defaultPassword),
				},
			},
		},
		VirtualPath: vdirSFTPPath,
	})
	mappedPathCrypt := filepath.Join(os.TempDir(), "crypt")
	folderNameCrypt := filepath.Base(mappedPathCrypt)
	vdirCryptPath := "/vdir/crypt"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name: folderNameCrypt,
			FsConfig: vfs.Filesystem{
				Provider: sdk.CryptedFilesystemProvider,
				CryptConfig: vfs.CryptFsConfig{
					Passphrase: kms.NewPlainSecret(defaultPassword),
				},
			},
			MappedPath: mappedPathCrypt,
		},
		VirtualPath: vdirCryptPath,
	})

	user, resp, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err, string(resp))
	baseDirDownPath := filepath.Join(os.TempDir(), "basedir-down")
	err = os.Mkdir(baseDirDownPath, os.ModePerm)
	assert.NoError(t, err)
	baseDir := filepath.Join(os.TempDir(), "basedir")
	err = os.Mkdir(baseDir, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(filepath.Join(baseDir, vdirSFTPPath), os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(filepath.Join(baseDir, vdirCryptPath), os.ModePerm)
	assert.NoError(t, err)
	err = createTestFile(filepath.Join(baseDir, vdirSFTPPath, testFileName), 32768)
	assert.NoError(t, err)
	err = createTestFile(filepath.Join(baseDir, vdirCryptPath, testFileName), 65535)
	assert.NoError(t, err)
	err = createTestFile(filepath.Join(baseDir, "vdir", testFileName), 65536)
	assert.NoError(t, err)

	remoteRootPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	err = scpUpload(filepath.Join(baseDir, "vdir"), remoteRootPath, true, false)
	assert.NoError(t, err)

	conn, client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer conn.Close()
		defer client.Close()
		info, err := client.Stat(path.Join(vdirCryptPath, testFileName))
		assert.NoError(t, err)
		assert.Equal(t, int64(65535), info.Size())
		info, err = client.Stat(path.Join(vdirSFTPPath, testFileName))
		assert.NoError(t, err)
		assert.Equal(t, int64(32768), info.Size())
		info, err = client.Stat(path.Join("/vdir", testFileName))
		assert.NoError(t, err)
		assert.Equal(t, int64(65536), info.Size())
	}

	err = scpDownload(baseDirDownPath, remoteRootPath, true, true)
	assert.NoError(t, err)

	assert.FileExists(t, filepath.Join(baseDirDownPath, user.Username, "vdir", testFileName))
	assert.FileExists(t, filepath.Join(baseDirDownPath, user.Username, vdirCryptPath, testFileName))
	assert.FileExists(t, filepath.Join(baseDirDownPath, user.Username, vdirSFTPPath, testFileName))

	if runtime.GOOS != osWindows {
		err = os.Chmod(filepath.Join(baseUser.GetHomeDir(), testFileName), 0001)
		assert.NoError(t, err)
		err = scpDownload(baseDirDownPath, remoteRootPath, true, true)
		assert.Error(t, err)
		err = os.Chmod(filepath.Join(baseUser.GetHomeDir(), testFileName), os.ModePerm)
		assert.NoError(t, err)
	}

	// now change the password for the base user, so SFTP folder will not work
	baseUser.Password = defaultPassword + "_mod"
	_, _, err = httpdtest.UpdateUser(baseUser, http.StatusOK, "")
	assert.NoError(t, err)

	err = scpUpload(filepath.Join(baseDir, "vdir"), remoteRootPath, true, false)
	assert.Error(t, err)

	err = scpDownload(baseDirDownPath, remoteRootPath, true, true)
	assert.Error(t, err)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderNameCrypt}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderNameSFTP}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(baseUser, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(baseUser.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPathCrypt)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPathSFTP)
	assert.NoError(t, err)
	err = os.RemoveAll(baseDir)
	assert.NoError(t, err)
	err = os.RemoveAll(baseDirDownPath)
	assert.NoError(t, err)
}

func TestSCPVirtualFoldersQuota(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	folderName1 := filepath.Base(mappedPath1)
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	folderName2 := filepath.Base(mappedPath2)
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName1,
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			Name:       folderName2,
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  0,
		QuotaSize:   0,
	})
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testBaseDirName := "test_dir"
	testBaseDirPath := filepath.Join(homeBasePath, testBaseDirName)
	testBaseDirDownName := "test_dir_down"
	testBaseDirDownPath := filepath.Join(homeBasePath, testBaseDirDownName)
	testFilePath := filepath.Join(homeBasePath, testBaseDirName, testFileName)
	testFilePath1 := filepath.Join(homeBasePath, testBaseDirName, testBaseDirName, testFileName)
	testFileSize := int64(131074)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = createTestFile(testFilePath1, testFileSize)
	assert.NoError(t, err)
	remoteDownPath1 := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", vdirPath1))
	remoteUpPath1 := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, vdirPath1)
	remoteDownPath2 := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", vdirPath2))
	remoteUpPath2 := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, vdirPath2)
	// we upload two times to test overwrite
	err = scpUpload(testBaseDirPath, remoteUpPath1, true, false)
	assert.NoError(t, err)
	err = scpDownload(testBaseDirDownPath, remoteDownPath1, true, true)
	assert.NoError(t, err)
	err = scpUpload(testBaseDirPath, remoteUpPath1, true, false)
	assert.NoError(t, err)
	err = scpDownload(testBaseDirDownPath, remoteDownPath1, true, true)
	assert.NoError(t, err)
	err = scpUpload(testBaseDirPath, remoteUpPath2, true, false)
	assert.NoError(t, err)
	err = scpDownload(testBaseDirDownPath, remoteDownPath2, true, true)
	assert.NoError(t, err)
	expectedQuotaFiles := 2
	expectedQuotaSize := testFileSize * 2
	user, _, err = httpdtest.GetUserByUsername(user.Username, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	f, _, err := httpdtest.GetFolderByName(folderName1, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaSize, f.UsedQuotaSize)
	assert.Equal(t, expectedQuotaFiles, f.UsedQuotaFiles)
	f, _, err = httpdtest.GetFolderByName(folderName2, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaSize, f.UsedQuotaSize)
	assert.Equal(t, expectedQuotaFiles, f.UsedQuotaFiles)

	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveFolder(vfs.BaseVirtualFolder{Name: folderName2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(testBaseDirPath)
	assert.NoError(t, err)
	err = os.RemoveAll(testBaseDirDownPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestSCPPermsSubDirs(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/somedir"] = []string{dataprovider.PermListItems, dataprovider.PermUpload}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	subPath := filepath.Join(user.GetHomeDir(), "somedir")
	testFileSize := int64(65535)
	err = os.MkdirAll(subPath, os.ModePerm)
	assert.NoError(t, err)
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/somedir")
	err = scpDownload(localPath, remoteDownPath, false, true)
	assert.Error(t, err, "download a dir with no permissions must fail")
	err = os.Remove(subPath)
	assert.NoError(t, err)
	err = createTestFile(subPath, testFileSize)
	assert.NoError(t, err)
	err = scpDownload(localPath, remoteDownPath, false, false)
	assert.NoError(t, err)
	if runtime.GOOS != osWindows {
		err = os.Chmod(subPath, 0001)
		assert.NoError(t, err)
		err = scpDownload(localPath, remoteDownPath, false, false)
		assert.Error(t, err, "download a file with no system permissions must fail")
		err = os.Chmod(subPath, os.ModePerm)
		assert.NoError(t, err)
	}
	err = os.Remove(localPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPPermCreateDirs(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(32760)
	testBaseDirName := "test_dir"
	testBaseDirPath := filepath.Join(homeBasePath, testBaseDirName)
	testFilePath1 := filepath.Join(homeBasePath, testBaseDirName, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	err = createTestFile(testFilePath1, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/tmp/")
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	assert.Error(t, err, "scp upload must fail, the user cannot create files in a missing dir")
	err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
	assert.Error(t, err, "scp upload must fail, the user cannot create new dirs")

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(testBaseDirPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPPermUpload(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermDownload, dataprovider.PermCreateDirs}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65536)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/tmp")
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	assert.Error(t, err, "scp upload must fail, the user cannot upload")
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPPermOverwrite(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65536)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/tmp")
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	assert.NoError(t, err)
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	assert.Error(t, err, "scp upload must fail, the user cannot ovewrite existing files")

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPPermDownload(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65537)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	assert.NoError(t, err)
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	err = scpDownload(localPath, remoteDownPath, false, false)
	assert.Error(t, err, "scp download must fail, the user cannot download")

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPQuotaSize(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	testFileSize := int64(65535)
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1
	u.QuotaSize = testFileSize + 1
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
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
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	assert.NoError(t, err)
	err = scpUpload(testFilePath, remoteUpPath+".quota", true, false)
	assert.Error(t, err, "user is over quota scp upload must fail")

	// now test quota limits while uploading the current file, we have 1 bytes remaining
	user.QuotaSize = testFileSize + 1
	user.QuotaFiles = 0
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	err = scpUpload(testFilePath2, remoteUpPath+".quota", true, false)
	assert.Error(t, err, "user is over quota scp upload must fail")
	// overwriting an existing file will work if the resulting size is lesser or equal than the current one
	err = scpUpload(testFilePath1, remoteUpPath, true, false)
	assert.Error(t, err)
	err = scpUpload(testFilePath2, remoteUpPath, true, false)
	assert.NoError(t, err)
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
	err = os.Remove(testFilePath2)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPEscapeHomeDir(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	err = os.MkdirAll(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	testDir := "testDir"
	linkPath := filepath.Join(homeBasePath, defaultUsername, testDir)
	err = os.Symlink(homeBasePath, linkPath)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join(testDir, testDir))
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.Error(t, err, "uploading to a dir with a symlink outside home dir must fail")
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testDir, testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	err = scpDownload(localPath, remoteDownPath, false, false)
	assert.Error(t, err, "scp download must fail, the requested file has a symlink outside user home")
	remoteDownPath = fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testDir))
	err = scpDownload(homeBasePath, remoteDownPath, false, true)
	assert.Error(t, err, "scp download must fail, the requested dir is a symlink outside user home")

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPUploadPaths(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	testDirName := "testDir"
	testDirPath := filepath.Join(user.GetHomeDir(), testDirName)
	err = os.MkdirAll(testDirPath, os.ModePerm)
	assert.NoError(t, err)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, testDirName)
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join(testDirName, testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.NoError(t, err)
	err = scpDownload(localPath, remoteDownPath, false, false)
	assert.NoError(t, err)
	// upload a file to a missing dir
	remoteUpPath = fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join(testDirName, testDirName, testFileName))
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.Error(t, err, "scp upload to a missing dir must fail")

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.Remove(localPath)
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPOverwriteDirWithFile(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	testDirPath := filepath.Join(user.GetHomeDir(), testFileName)
	err = os.MkdirAll(testDirPath, os.ModePerm)
	assert.NoError(t, err)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.Error(t, err, "copying a file over an existing dir must fail")

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPRemoteToRemote(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	if runtime.GOOS == osWindows {
		t.Skip("scp between remote hosts is not supported on Windows")
	}
	usePubKey := true
	user, _, err := httpdtest.AddUser(getTestUser(usePubKey), http.StatusCreated)
	assert.NoError(t, err)
	u := getTestUser(usePubKey)
	u.Username += "1"
	u.HomeDir += "1"
	user1, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	remote1UpPath := fmt.Sprintf("%v@127.0.0.1:%v", user1.Username, path.Join("/", testFileName))
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.NoError(t, err)
	err = scpUpload(remoteUpPath, remote1UpPath, false, true)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user1.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPErrors(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	u := getTestUser(true)
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	assert.NoError(t, err)
	testFileSize := int64(524288)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, "/")
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	localPath := filepath.Join(homeBasePath, "scp_download.dat")
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.NoError(t, err)
	user.UploadBandwidth = 512
	user.DownloadBandwidth = 512
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	cmd := getScpDownloadCommand(localPath, remoteDownPath, false, false)
	go func() {
		err := cmd.Run()
		assert.Error(t, err, "SCP download must fail")
	}()
	waitForActiveTransfers(t)
	// wait some additional arbitrary time to wait for transfer activity to happen
	// it is need to reach all the code in CheckIdleConnections
	time.Sleep(100 * time.Millisecond)
	err = cmd.Process.Kill()
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 }, 2*time.Second, 100*time.Millisecond)
	cmd = getScpUploadCommand(testFilePath, remoteUpPath, false, false)
	go func() {
		err := cmd.Run()
		assert.Error(t, err, "SCP upload must fail")
	}()
	waitForActiveTransfers(t)
	// wait some additional arbitrary time to wait for transfer activity to happen
	// it is need to reach all the code in CheckIdleConnections
	time.Sleep(100 * time.Millisecond)
	err = cmd.Process.Kill()
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 }, 2*time.Second, 100*time.Millisecond)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	os.Remove(localPath)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpdtest.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

// End SCP tests

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

func getTestUser(usePubKey bool) dataprovider.User {
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
	if usePubKey {
		user.PublicKeys = []string{testPubKey}
		user.Password = ""
	}
	return user
}

func getTestSFTPUser(usePubKey bool) dataprovider.User {
	u := getTestUser(usePubKey)
	u.Username = defaultSFTPUsername
	u.FsConfig.Provider = sdk.SFTPFilesystemProvider
	u.FsConfig.SFTPConfig.Endpoint = sftpServerAddr
	u.FsConfig.SFTPConfig.Username = defaultUsername
	u.FsConfig.SFTPConfig.Password = kms.NewPlainSecret(defaultPassword)
	if usePubKey {
		u.FsConfig.SFTPConfig.PrivateKey = kms.NewPlainSecret(testPrivateKey)
		u.FsConfig.SFTPConfig.Fingerprints = hostKeyFPs
	}
	return u
}

func runSSHCommand(command string, user dataprovider.User, usePubKey bool) ([]byte, error) {
	var sshSession *ssh.Session
	var output []byte
	config := &ssh.ClientConfig{
		User: user.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	if usePubKey {
		key, err := ssh.ParsePrivateKey([]byte(testPrivateKey))
		if err != nil {
			return output, err
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	} else {
		config.Auth = []ssh.AuthMethod{ssh.Password(defaultPassword)}
	}
	conn, err := ssh.Dial("tcp", sftpServerAddr, config)
	if err != nil {
		return output, err
	}
	defer conn.Close()
	sshSession, err = conn.NewSession()
	if err != nil {
		return output, err
	}
	var stdout, stderr bytes.Buffer
	sshSession.Stdout = &stdout
	sshSession.Stderr = &stderr
	err = sshSession.Run(command)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %v: %v", command, stderr.Bytes())
	}
	return stdout.Bytes(), err
}

func getSignerForUserCert(certBytes []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey([]byte(testPrivateKey))
	if err != nil {
		return nil, err
	}
	cert, _, _, _, err := ssh.ParseAuthorizedKey(certBytes) //nolint:dogsled
	if err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(cert.(*ssh.Certificate), signer)
}

func getSftpClientWithAddr(user dataprovider.User, usePubKey bool, addr string) (*ssh.Client, *sftp.Client, error) {
	var sftpClient *sftp.Client
	config := &ssh.ClientConfig{
		User: user.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	if usePubKey {
		signer, err := ssh.ParsePrivateKey([]byte(testPrivateKey))
		if err != nil {
			return nil, nil, err
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		if user.Password != "" {
			config.Auth = []ssh.AuthMethod{ssh.Password(user.Password)}
		} else {
			config.Auth = []ssh.AuthMethod{ssh.Password(defaultPassword)}
		}
	}
	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return conn, sftpClient, err
	}
	sftpClient, err = sftp.NewClient(conn)
	if err != nil {
		conn.Close()
	}
	return conn, sftpClient, err
}

func getSftpClient(user dataprovider.User, usePubKey bool) (*ssh.Client, *sftp.Client, error) {
	return getSftpClientWithAddr(user, usePubKey, sftpServerAddr)
}

func getKeyboardInteractiveSftpClient(user dataprovider.User, answers []string) (*ssh.Client, *sftp.Client, error) {
	var sftpClient *sftp.Client
	config := &ssh.ClientConfig{
		User: user.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				return answers, nil
			}),
		},
	}
	conn, err := ssh.Dial("tcp", sftpServerAddr, config)
	if err != nil {
		return nil, sftpClient, err
	}
	sftpClient, err = sftp.NewClient(conn)
	if err != nil {
		conn.Close()
	}
	return conn, sftpClient, err
}

func getCustomAuthSftpClient(user dataprovider.User, authMethods []ssh.AuthMethod, addr string) (*ssh.Client, *sftp.Client, error) {
	var sftpClient *sftp.Client
	config := &ssh.ClientConfig{
		User: user.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Auth: authMethods,
	}
	var err error
	var conn *ssh.Client
	if len(addr) > 0 {
		conn, err = ssh.Dial("tcp", addr, config)
	} else {
		conn, err = ssh.Dial("tcp", sftpServerAddr, config)
	}
	if err != nil {
		return conn, sftpClient, err
	}
	sftpClient, err = sftp.NewClient(conn)
	if err != nil {
		conn.Close()
	}
	return conn, sftpClient, err
}

func createTestFile(path string, size int64) error {
	baseDir := filepath.Dir(path)
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
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

func appendToTestFile(path string, size int64) error {
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	written, err := io.Copy(f, bytes.NewReader(content))
	if err != nil {
		return err
	}
	if written != size {
		return fmt.Errorf("write error, written: %v/%v", written, size)
	}
	return nil
}

func checkBasicSFTP(client *sftp.Client) error {
	_, err := client.Getwd()
	if err != nil {
		return err
	}
	_, err = client.ReadDir(".")
	return err
}

func writeSFTPFile(name string, size int64, client *sftp.Client) error {
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return err
	}
	f, err := client.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, bytes.NewBuffer(content))
	if err != nil {
		f.Close()
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	info, err := client.Stat(name)
	if err != nil {
		return err
	}
	if info.Size() != size {
		return fmt.Errorf("file size mismatch, wanted %v, actual %v", size, info.Size())
	}
	return nil
}

func sftpUploadFile(localSourcePath string, remoteDestPath string, expectedSize int64, client *sftp.Client) error {
	srcFile, err := os.Open(localSourcePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	destFile, err := client.Create(remoteDestPath)
	if err != nil {
		return err
	}
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		destFile.Close()
		return err
	}
	// we need to close the file to trigger the server side close method
	// we cannot defer closing otherwise Stat will fail for upload atomic mode
	destFile.Close()
	if expectedSize > 0 {
		fi, err := client.Stat(remoteDestPath)
		if err != nil {
			return err
		}
		if fi.Size() != expectedSize {
			return fmt.Errorf("uploaded file size does not match, actual: %v, expected: %v", fi.Size(), expectedSize)
		}
	}
	return err
}

func sftpUploadResumeFile(localSourcePath string, remoteDestPath string, expectedSize int64, invalidOffset bool, //nolint:unparam
	client *sftp.Client) error {
	srcFile, err := os.Open(localSourcePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	fi, err := client.Lstat(remoteDestPath)
	if err != nil {
		return err
	}
	if !invalidOffset {
		_, err = srcFile.Seek(fi.Size(), 0)
		if err != nil {
			return err
		}
	}
	destFile, err := client.OpenFile(remoteDestPath, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return err
	}
	if !invalidOffset {
		_, err = destFile.Seek(fi.Size(), 0)
		if err != nil {
			return err
		}
	}
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		destFile.Close()
		return err
	}
	// we need to close the file to trigger the server side close method
	// we cannot defer closing otherwise Stat will fail for upload atomic mode
	destFile.Close()
	if expectedSize > 0 {
		fi, err := client.Lstat(remoteDestPath)
		if err != nil {
			return err
		}
		if fi.Size() != expectedSize {
			return fmt.Errorf("uploaded file size does not match, actual: %v, expected: %v", fi.Size(), expectedSize)
		}
	}
	return err
}

func sftpDownloadFile(remoteSourcePath string, localDestPath string, expectedSize int64, client *sftp.Client) error {
	downloadDest, err := os.Create(localDestPath)
	if err != nil {
		return err
	}
	defer downloadDest.Close()
	sftpSrcFile, err := client.Open(remoteSourcePath)
	if err != nil {
		return err
	}
	defer sftpSrcFile.Close()
	_, err = io.Copy(downloadDest, sftpSrcFile)
	if err != nil {
		return err
	}
	err = downloadDest.Sync()
	if err != nil {
		return err
	}
	if expectedSize > 0 {
		fi, err := downloadDest.Stat()
		if err != nil {
			return err
		}
		if fi.Size() != expectedSize {
			return fmt.Errorf("downloaded file size does not match, actual: %v, expected: %v", fi.Size(), expectedSize)
		}
	}
	return err
}

func sftpUploadNonBlocking(localSourcePath string, remoteDestPath string, expectedSize int64, client *sftp.Client) <-chan error {
	c := make(chan error, 1)
	go func() {
		c <- sftpUploadFile(localSourcePath, remoteDestPath, expectedSize, client)
	}()
	return c
}

func sftpDownloadNonBlocking(remoteSourcePath string, localDestPath string, expectedSize int64, client *sftp.Client) <-chan error {
	c := make(chan error, 1)
	go func() {
		c <- sftpDownloadFile(remoteSourcePath, localDestPath, expectedSize, client)
	}()
	return c
}

func scpUpload(localPath, remotePath string, preserveTime, remoteToRemote bool) error {
	cmd := getScpUploadCommand(localPath, remotePath, preserveTime, remoteToRemote)
	return cmd.Run()
}

func scpDownload(localPath, remotePath string, preserveTime, recursive bool) error {
	cmd := getScpDownloadCommand(localPath, remotePath, preserveTime, recursive)
	return cmd.Run()
}

func getScpDownloadCommand(localPath, remotePath string, preserveTime, recursive bool) *exec.Cmd {
	var args []string
	if preserveTime {
		args = append(args, "-p")
	}
	if recursive {
		args = append(args, "-r")
	}
	args = append(args, "-P")
	args = append(args, "2022")
	args = append(args, "-o")
	args = append(args, "StrictHostKeyChecking=no")
	args = append(args, "-i")
	args = append(args, privateKeyPath)
	args = append(args, remotePath)
	args = append(args, localPath)
	return exec.Command(scpPath, args...)
}

func getScpUploadCommand(localPath, remotePath string, preserveTime, remoteToRemote bool) *exec.Cmd {
	var args []string
	if remoteToRemote {
		args = append(args, "-3")
	}
	if preserveTime {
		args = append(args, "-p")
	}
	fi, err := os.Stat(localPath)
	if err == nil {
		if fi.IsDir() {
			args = append(args, "-r")
		}
	}
	args = append(args, "-P")
	args = append(args, "2022")
	args = append(args, "-o")
	args = append(args, "StrictHostKeyChecking=no")
	args = append(args, "-o")
	args = append(args, "HostKeyAlgorithms=+ssh-rsa")
	args = append(args, "-i")
	args = append(args, privateKeyPath)
	args = append(args, localPath)
	args = append(args, remotePath)
	return exec.Command(scpPath, args...)
}

func computeHashForFile(hasher hash.Hash, path string) (string, error) {
	hash := ""
	f, err := os.Open(path)
	if err != nil {
		return hash, err
	}
	defer f.Close()
	_, err = io.Copy(hasher, f)
	if err == nil {
		hash = fmt.Sprintf("%x", hasher.Sum(nil))
	}
	return hash, err
}

func waitForActiveTransfers(t *testing.T) {
	assert.Eventually(t, func() bool {
		for _, stat := range common.Connections.GetStats() {
			if len(stat.Transfers) > 0 {
				return true
			}
		}
		return false
	}, 1*time.Second, 50*time.Millisecond)
}

func checkSystemCommands() {
	var err error
	gitPath, err = exec.LookPath("git")
	if err != nil {
		logger.Warn(logSender, "", "unable to get git command. GIT tests will be skipped, err: %v", err)
		logger.WarnToConsole("unable to get git command. GIT tests will be skipped, err: %v", err)
		gitPath = ""
	}

	sshPath, err = exec.LookPath("ssh")
	if err != nil {
		logger.Warn(logSender, "", "unable to get ssh command. GIT tests will be skipped, err: %v", err)
		logger.WarnToConsole("unable to get ssh command. GIT tests will be skipped, err: %v", err)
		gitPath = ""
	}
	hookCmdPath, err = exec.LookPath("true")
	if err != nil {
		logger.Warn(logSender, "", "unable to get hook command: %v", err)
		logger.WarnToConsole("unable to get hook command: %v", err)
	}
	scpPath, err = exec.LookPath("scp")
	if err != nil {
		logger.Warn(logSender, "", "unable to get scp command. SCP tests will be skipped, err: %v", err)
		logger.WarnToConsole("unable to get scp command. SCP tests will be skipped, err: %v", err)
		scpPath = ""
	}
}

func initGitRepo(path string) ([]byte, error) {
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return nil, err
	}
	args := []string{"init", "--bare"}
	cmd := exec.Command(gitPath, args...)
	cmd.Dir = path
	return cmd.CombinedOutput()
}

func pushToGitRepo(repoPath string) ([]byte, error) {
	cmd := exec.Command(gitPath, "push")
	cmd.Dir = repoPath
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GIT_SSH=%v", gitWrapPath))
	return cmd.CombinedOutput()
}

func cloneGitRepo(basePath, remotePath, username string) ([]byte, error) {
	remoteURL := fmt.Sprintf("ssh://%v@127.0.0.1:2022%v", username, remotePath)
	args := []string{"clone", remoteURL}
	cmd := exec.Command(gitPath, args...)
	cmd.Dir = basePath
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GIT_SSH=%v", gitWrapPath))
	return cmd.CombinedOutput()
}

func addFileToGitRepo(repoPath string, fileSize int64) ([]byte, error) {
	path := filepath.Join(repoPath, "test")
	err := createTestFile(path, fileSize)
	if err != nil {
		return []byte(""), err
	}
	cmd := exec.Command(gitPath, "config", "user.email", "testuser@example.com")
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, err
	}
	cmd = exec.Command(gitPath, "config", "user.name", "testuser")
	cmd.Dir = repoPath
	out, err = cmd.CombinedOutput()
	if err != nil {
		return out, err
	}
	cmd = exec.Command(gitPath, "add", "test")
	cmd.Dir = repoPath
	out, err = cmd.CombinedOutput()
	if err != nil {
		return out, err
	}
	cmd = exec.Command(gitPath, "commit", "-am", "test")
	cmd.Dir = repoPath
	return cmd.CombinedOutput()
}

func getKeyboardInteractiveScriptForBuiltinChecks(addPasscode bool, result int) []byte {
	content := []byte("#!/bin/sh\n\n")
	echos := []bool{false}
	q, _ := json.Marshal([]string{"Password: "})
	e, _ := json.Marshal(echos)
	content = append(content, []byte(fmt.Sprintf("echo '{\"questions\":%v,\"echos\":%v,\"check_password\":1}'\n", string(q), string(e)))...)
	content = append(content, []byte("read ANSWER\n\n")...)
	content = append(content, []byte("if test \"$ANSWER\" != \"OK\"; then\n")...)
	content = append(content, []byte("exit 1\n")...)
	content = append(content, []byte("fi\n\n")...)
	if addPasscode {
		q, _ := json.Marshal([]string{"Passcode: "})
		content = append(content, []byte(fmt.Sprintf("echo '{\"questions\":%v,\"echos\":%v,\"check_password\":2}'\n", string(q), string(e)))...)
		content = append(content, []byte("read ANSWER\n\n")...)
		content = append(content, []byte("if test \"$ANSWER\" != \"OK\"; then\n")...)
		content = append(content, []byte("exit 1\n")...)
		content = append(content, []byte("fi\n\n")...)
	}
	content = append(content, []byte(fmt.Sprintf("echo '{\"auth_result\":%v}'\n", result))...)
	return content
}

func getKeyboardInteractiveScriptContent(questions []string, sleepTime int, nonJSONResponse bool, result int) []byte {
	content := []byte("#!/bin/sh\n\n")
	q, _ := json.Marshal(questions)
	echos := []bool{}
	for index := range questions {
		echos = append(echos, index%2 == 0)
	}
	e, _ := json.Marshal(echos)
	if nonJSONResponse {
		content = append(content, []byte(fmt.Sprintf("echo 'questions: %v echos: %v\n", string(q), string(e)))...)
	} else {
		content = append(content, []byte(fmt.Sprintf("echo '{\"questions\":%v,\"echos\":%v}'\n", string(q), string(e)))...)
	}
	for index := range questions {
		content = append(content, []byte(fmt.Sprintf("read ANSWER%v\n", index))...)
	}
	if sleepTime > 0 {
		content = append(content, []byte(fmt.Sprintf("sleep %v\n", sleepTime))...)
	}
	content = append(content, []byte(fmt.Sprintf("echo '{\"auth_result\":%v}'\n", result))...)
	return content
}

func getExtAuthScriptContent(user dataprovider.User, nonJSONResponse, emptyResponse bool, username string) []byte {
	extAuthContent := []byte("#!/bin/sh\n\n")
	if emptyResponse {
		return extAuthContent
	}
	extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("if test \"$SFTPGO_AUTHD_USERNAME\" = \"%v\"; then\n", user.Username))...)
	if len(username) > 0 {
		user.Username = username
	}
	u, _ := json.Marshal(user)
	if nonJSONResponse {
		extAuthContent = append(extAuthContent, []byte("echo 'text response'\n")...)
	} else {
		extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("echo '%v'\n", string(u)))...)
	}
	extAuthContent = append(extAuthContent, []byte("else\n")...)
	if nonJSONResponse {
		extAuthContent = append(extAuthContent, []byte("echo 'text response'\n")...)
	} else {
		extAuthContent = append(extAuthContent, []byte("echo '{\"username\":\"\"}'\n")...)
	}
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

func getCheckPwdScriptsContents(status int, toVerify string) []byte {
	content := []byte("#!/bin/sh\n\n")
	content = append(content, []byte(fmt.Sprintf("echo '{\"status\":%v,\"to_verify\":\"%v\"}'\n", status, toVerify))...)
	if status > 0 {
		content = append(content, []byte("exit 0")...)
	} else {
		content = append(content, []byte("exit 1")...)
	}
	return content
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

func getHostKeyFingerprint(name string) (string, error) {
	privateBytes, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(private.PublicKey()), nil
}

func getHostKeysFingerprints(hostKeys []string) {
	for _, k := range hostKeys {
		fp, err := getHostKeyFingerprint(filepath.Join(configDir, k))
		if err != nil {
			logger.ErrorToConsole("unable to get fingerprint for host key %#v: %v", k, err)
			os.Exit(1)
		}
		hostKeyFPs = append(hostKeyFPs, fp)
	}
}

func createInitialFiles(scriptArgs string) {
	pubKeyPath = filepath.Join(homeBasePath, "ssh_key.pub")
	privateKeyPath = filepath.Join(homeBasePath, "ssh_key")
	trustedCAUserKey = filepath.Join(homeBasePath, "ca_user_key")
	gitWrapPath = filepath.Join(homeBasePath, "gitwrap.sh")
	extAuthPath = filepath.Join(homeBasePath, "extauth.sh")
	preLoginPath = filepath.Join(homeBasePath, "prelogin.sh")
	postConnectPath = filepath.Join(homeBasePath, "postconnect.sh")
	checkPwdPath = filepath.Join(homeBasePath, "checkpwd.sh")
	preDownloadPath = filepath.Join(homeBasePath, "predownload.sh")
	preUploadPath = filepath.Join(homeBasePath, "preupload.sh")
	revokeUserCerts = filepath.Join(homeBasePath, "revoked_certs.json")
	err := os.WriteFile(pubKeyPath, []byte(testPubKey+"\n"), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save public key to file: %v", err)
	}
	err = os.WriteFile(privateKeyPath, []byte(testPrivateKey+"\n"), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save private key to file: %v", err)
	}
	err = os.WriteFile(gitWrapPath, []byte(fmt.Sprintf("%v -i %v -oStrictHostKeyChecking=no %v\n",
		sshPath, privateKeyPath, scriptArgs)), os.ModePerm)
	if err != nil {
		logger.WarnToConsole("unable to save gitwrap shell script: %v", err)
	}
	err = os.WriteFile(trustedCAUserKey, []byte(testCAUserKey), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save trusted CA user key: %v", err)
	}
	err = os.WriteFile(revokeUserCerts, []byte(`[]`), 0644)
	if err != nil {
		logger.WarnToConsole("unable to save revoked user certs: %v", err)
	}
}
