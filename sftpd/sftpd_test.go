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
	"io/ioutil"
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

	"github.com/pkg/sftp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/common"
	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/kms"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	logSender       = "sftpdTesting"
	sftpServerAddr  = "127.0.0.1:2022"
	sftpSrvAddr2222 = "127.0.0.1:2222"
	defaultUsername = "test_user_sftp"
	defaultPassword = "test_password"
	testPubKey      = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0= nicola@p1"
	testPubKey1     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCd60+/j+y8f0tLftihWV1YN9RSahMI9btQMDIMqts/jeNbD8jgoogM3nhF7KxfcaMKURuD47KC4Ey6iAJUJ0sWkSNNxOcIYuvA+5MlspfZDsa8Ag76Fe1vyz72WeHMHMeh/hwFo2TeIeIXg480T1VI6mzfDrVp2GzUx0SS0dMsQBjftXkuVR8YOiOwMCAH2a//M1OrvV7d/NBk6kBN0WnuIBb2jKm15PAA7+jQQG7tzwk2HedNH3jeL5GH31xkSRwlBczRK0xsCQXehAlx6cT/e/s44iJcJTHfpPKoSk6UAhPJYe7Z1QnuoawY9P9jQaxpyeImBZxxUEowhjpj2avBxKdRGBVK8R7EL8tSOeLbhdyWe5Mwc1+foEbq9Zz5j5Kd+hn3Wm1UnsGCrXUUUoZp1jnlNl0NakCto+5KmqnT9cHxaY+ix2RLUWAZyVFlRq71OYux1UHJnEJPiEI1/tr4jFBSL46qhQZv/TfpkfVW8FLz0lErfqu0gQEZnNHr3Fc= nicola@p1"
	testPrivateKey  = `-----BEGIN OPENSSH PRIVATE KEY-----
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
	configDir       = ".."
	osWindows       = "windows"
	testFileName    = "test_file_sftp.dat"
	testDLFileName  = "test_download_sftp.dat"
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
	gitWrapPath      string
	extAuthPath      string
	keyIntAuthPath   string
	preLoginPath     string
	postConnectPath  string
	checkPwdPath     string
	logFilePath      string
)

func TestMain(m *testing.M) {
	logFilePath = filepath.Join(configDir, "sftpgo_sftpd_test.log")
	loginBannerFileName := "login_banner"
	loginBannerFile := filepath.Join(configDir, loginBannerFileName)
	logger.InitLogger(logFilePath, 5, 1, 28, false, zerolog.DebugLevel)
	err := ioutil.WriteFile(loginBannerFile, []byte("simple login banner\n"), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error creating login banner: %v", err)
	}
	err = config.LoadConfig(configDir, "")
	if err != nil {
		logger.ErrorToConsole("error loading configuration: %v", err)
		os.Exit(1)
	}
	providerConf := config.GetProviderConf()
	logger.InfoToConsole("Starting SFTPD tests, provider: %v", providerConf.Driver)

	commonConf := config.GetCommonConfig()
	// we run the test cases with UploadMode atomic and resume support. The non atomic code path
	// simply does not execute some code so if it works in atomic mode will
	// work in non atomic mode too
	commonConf.UploadMode = 2
	homeBasePath = os.TempDir()
	checkSystemCommands()
	var scriptArgs string
	if runtime.GOOS == osWindows {
		scriptArgs = "%*"
	} else {
		commonConf.Actions.ExecuteOn = []string{"download", "upload", "rename", "delete", "ssh_cmd"}
		commonConf.Actions.Hook = hookCmdPath
		scriptArgs = "$@"
	}

	common.Initialize(commonConf)

	err = dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		logger.ErrorToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}

	httpConfig := config.GetHTTPConfig()
	httpConfig.Initialize(configDir)
	kmsConfig := config.GetKMSConfig()
	err = kmsConfig.Initialize()
	if err != nil {
		logger.ErrorToConsole("error initializing kms: %v", err)
		os.Exit(1)
	}

	sftpdConf := config.GetSFTPDConfig()
	httpdConf := config.GetHTTPDConfig()
	sftpdConf.BindPort = 2022
	sftpdConf.KexAlgorithms = []string{"curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384"}
	sftpdConf.Ciphers = []string{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com",
		"aes256-ctr"}
	sftpdConf.MACs = []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"}
	sftpdConf.LoginBannerFile = loginBannerFileName
	// we need to test all supported ssh commands
	sftpdConf.EnabledSSHCommands = []string{"*"}

	keyIntAuthPath = filepath.Join(homeBasePath, "keyintauth.sh")
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), os.ModePerm)
	if err != nil {
		logger.ErrorToConsole("error writing keyboard interactive script: %v", err)
		os.Exit(1)
	}
	sftpdConf.KeyboardInteractiveHook = keyIntAuthPath

	pubKeyPath = filepath.Join(homeBasePath, "ssh_key.pub")
	privateKeyPath = filepath.Join(homeBasePath, "ssh_key")
	trustedCAUserKey = filepath.Join(homeBasePath, "ca_user_key")
	gitWrapPath = filepath.Join(homeBasePath, "gitwrap.sh")
	extAuthPath = filepath.Join(homeBasePath, "extauth.sh")
	preLoginPath = filepath.Join(homeBasePath, "prelogin.sh")
	postConnectPath = filepath.Join(homeBasePath, "postconnect.sh")
	checkPwdPath = filepath.Join(homeBasePath, "checkpwd.sh")
	err = ioutil.WriteFile(pubKeyPath, []byte(testPubKey+"\n"), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save public key to file: %v", err)
	}
	err = ioutil.WriteFile(privateKeyPath, []byte(testPrivateKey+"\n"), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save private key to file: %v", err)
	}
	err = ioutil.WriteFile(gitWrapPath, []byte(fmt.Sprintf("%v -i %v -oStrictHostKeyChecking=no %v\n",
		sshPath, privateKeyPath, scriptArgs)), os.ModePerm)
	if err != nil {
		logger.WarnToConsole("unable to save gitwrap shell script: %v", err)
	}
	err = ioutil.WriteFile(trustedCAUserKey, []byte(testCAUserKey), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save trusted CA user key: %v", err)
	}
	sftpdConf.TrustedUserCAKeys = append(sftpdConf.TrustedUserCAKeys, trustedCAUserKey)

	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.ErrorToConsole("could not start SFTP server: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := httpdConf.Initialize(configDir, false); err != nil {
			logger.ErrorToConsole("could not start HTTP server: %v", err)
			os.Exit(1)
		}
	}()

	waitTCPListening(fmt.Sprintf("%s:%d", sftpdConf.BindAddress, sftpdConf.BindPort))
	waitTCPListening(fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort))

	sftpdConf.BindPort = 2222
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

	waitTCPListening(fmt.Sprintf("%s:%d", sftpdConf.BindAddress, sftpdConf.BindPort))

	sftpdConf.BindPort = 2224
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

	waitTCPListening(fmt.Sprintf("%s:%d", sftpdConf.BindAddress, sftpdConf.BindPort))

	exitCode := m.Run()
	os.Remove(logFilePath)
	os.Remove(loginBannerFile)
	os.Remove(pubKeyPath)
	os.Remove(privateKeyPath)
	os.Remove(trustedCAUserKey)
	os.Remove(gitWrapPath)
	os.Remove(extAuthPath)
	os.Remove(preLoginPath)
	os.Remove(postConnectPath)
	os.Remove(keyIntAuthPath)
	os.Remove(checkPwdPath)
	os.Exit(exitCode)
}

func TestInitialization(t *testing.T) {
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.BindPort = 2022
	sftpdConf.LoginBannerFile = "invalid_file"
	sftpdConf.EnabledSSHCommands = append(sftpdConf.EnabledSSHCommands, "ls")
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.KeyboardInteractiveHook = "invalid_file"
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.KeyboardInteractiveHook = filepath.Join(homeBasePath, "invalid_file")
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.BindPort = 4444
	common.Config.ProxyProtocol = 1
	common.Config.ProxyAllowed = []string{"1270.0.0.1"}
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.HostKeys = []string{"missing key"}
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.HostKeys = nil
	sftpdConf.TrustedUserCAKeys = []string{"missing ca key"}
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
}

func TestBasicSFTPHandling(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaSize = 6553600
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		_, err = client.Lstat(testFileName)
		assert.Error(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles-1, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize-testFileSize, user.UsedQuotaSize)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	status := sftpd.GetStatus()
	assert.True(t, status.IsActive)
}

func TestOpenReadWrite(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaSize = 6553600
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestOpenReadWritePerm(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	// we cannot read inside "/sub"
	u.Permissions["/sub"] = []string{dataprovider.PermUpload, dataprovider.PermListItems}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestConcurrency(t *testing.T) {
	usePubKey := true
	numLogins := 50
	u := getTestUser(usePubKey)
	u.QuotaFiles = numLogins + 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
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

			client, err := getSftpClient(user, usePubKey)
			if assert.NoError(t, err) {
				err = checkBasicSFTP(client)
				assert.NoError(t, err)
				err = sftpUploadFile(testFilePath, testFileName+strconv.Itoa(counter), testFileSize, client)
				assert.NoError(t, err)
				assert.Greater(t, common.Connections.GetActiveSessions(defaultUsername), 0)
				client.Close()
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

	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		files, err := client.ReadDir(".")
		assert.NoError(t, err)
		assert.Len(t, files, numLogins)
		client.Close()
	}

	assert.Eventually(t, func() bool {
		return common.Connections.GetActiveSessions(defaultUsername) == 0
	}, 1*time.Second, 50*time.Millisecond)

	assert.Eventually(t, func() bool {
		return len(common.Connections.GetStats()) == 0
	}, 1*time.Second, 50*time.Millisecond)

	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestProxyProtocol(t *testing.T) {
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	// remove the home dir to test auto creation
	err = os.RemoveAll(user.HomeDir)
	assert.NoError(t, err)
	client, err := getSftpClientWithAddr(user, usePubKey, sftpSrvAddr2222)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	client, err = getSftpClientWithAddr(user, usePubKey, "127.0.0.1:2224")
	if !assert.Error(t, err) {
		client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadResume(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		assert.Error(t, err, "file upload resume with invalid offset must fail")
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDirCommands(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	// remove the home dir to test auto creation
	err = os.RemoveAll(user.HomeDir)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRemove(t *testing.T) {
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLink(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestStat(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestStatChownChmod(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("chown is not supported on Windows, chmod is partially supported")
	}
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestChtimes(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		testDir := "test"
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
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

// basic tests to verify virtual chroot, should be improved to cover more cases ...
func TestEscapeHomeDir(t *testing.T) {
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	dirOutsideHome := filepath.Join(homeBasePath, defaultUsername+"1", "dir")
	err = os.MkdirAll(dirOutsideHome, os.ModePerm)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "SSH_FX_FAILURE")
		}
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(filepath.Join(homeBasePath, defaultUsername+"1"))
	assert.NoError(t, err)
}

func TestHomeSpecialChars(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.HomeDir = filepath.Join(homeBasePath, "abc açà#&%lk")
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLogin(t *testing.T) {
	u := getTestUser(false)
	u.PublicKeys = []string{testPubKey}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, false)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, user.LastLogin, int64(0), "last login must be updated after a successful login: %v", user.LastLogin)
	}
	client, err = getSftpClient(user, true)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Password = "invalid password"
	client, err = getSftpClient(user, false)
	if !assert.Error(t, err, "login with invalid password must fail") {
		client.Close()
	}
	// testPubKey1 is not authorized
	user.PublicKeys = []string{testPubKey1}
	user.Password = ""
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, true)
	if !assert.Error(t, err, "login with invalid public key must fail") {
		defer client.Close()
	}
	// login a user with multiple public keys, only the second one is valid
	user.PublicKeys = []string{testPubKey1, testPubKey}
	user.Password = ""
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, true)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginUserCert(t *testing.T) {
	u := getTestUser(true)
	u.PublicKeys = []string{testCertValid, testCertUntrustedCA, testHostCert, testCertOtherSourceAddress, testCertExpired}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	// try login using a cert signed from a trusted CA
	signer, err := getSignerForUserCert([]byte(testCertValid))
	assert.NoError(t, err)
	client, err := getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	// try login using a cert signed from an untrusted CA
	signer, err = getSignerForUserCert([]byte(testCertUntrustedCA))
	assert.NoError(t, err)
	client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
	}
	// try login using an host certificate instead of an user certificate
	signer, err = getSignerForUserCert([]byte(testHostCert))
	assert.NoError(t, err)
	client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
	}
	// try login using a user certificate with an authorized source address different from localhost
	signer, err = getSignerForUserCert([]byte(testCertOtherSourceAddress))
	assert.NoError(t, err)
	client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
	}
	// try login using an expired certificate
	signer, err = getSignerForUserCert([]byte(testCertExpired))
	assert.NoError(t, err)
	client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	// now login with a username not in the set of valid principals for the given certificate
	u.Username += "1"
	user, _, err = httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)

	signer, err = getSignerForUserCert([]byte(testCertValid))
	assert.NoError(t, err)
	client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)}, "")
	if !assert.Error(t, err) {
		client.Close()
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, true)
	if !assert.Error(t, err, "login with public key is disallowed and must fail") {
		client.Close()
	}
	client, err = getSftpClient(user, true)
	if !assert.Error(t, err, "login with password is disallowed and must fail") {
		client.Close()
	}
	signer, _ := ssh.ParsePrivateKey([]byte(testPrivateKey))
	authMethods := []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.Password(defaultPassword),
	}
	client, err = getCustomAuthSftpClient(user, authMethods, "")
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	client, err = getCustomAuthSftpClient(user, authMethods, sftpSrvAddr2222)
	if !assert.Error(t, err, "password auth is disabled on port 2222, multi-step auth must fail") {
		client.Close()
	}
	authMethods = []ssh.AuthMethod{
		ssh.Password(defaultPassword),
		ssh.PublicKeys(signer),
	}
	_, err = getCustomAuthSftpClient(user, authMethods, "")
	assert.Error(t, err, "multi step auth login with wrong order must fail")
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), os.ModePerm)
	assert.NoError(t, err)
	client, err := getSftpClient(user, true)
	if !assert.Error(t, err, "login with public key is disallowed and must fail") {
		client.Close()
	}

	signer, _ := ssh.ParsePrivateKey([]byte(testPrivateKey))
	authMethods := []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			return []string{"1", "2"}, nil
		}),
	}
	client, err = getCustomAuthSftpClient(user, authMethods, "")
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	client, err = getCustomAuthSftpClient(user, authMethods, sftpSrvAddr2222)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	authMethods = []ssh.AuthMethod{
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			return []string{"1", "2"}, nil
		}),
		ssh.PublicKeys(signer),
	}
	_, err = getCustomAuthSftpClient(user, authMethods, "")
	assert.Error(t, err, "multi step auth login with wrong order must fail")

	authMethods = []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.Password(defaultPassword),
	}
	_, err = getCustomAuthSftpClient(user, authMethods, "")
	assert.Error(t, err, "multi step auth login with wrong method must fail")

	user.Filters.DeniedLoginMethods = nil
	user.Filters.DeniedLoginMethods = append(user.Filters.DeniedLoginMethods, []string{
		dataprovider.SSHLoginMethodKeyAndKeyboardInt,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}...)
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	_, err = getCustomAuthSftpClient(user, authMethods, sftpSrvAddr2222)
	assert.Error(t, err)
	client, err = getCustomAuthSftpClient(user, authMethods, "")
	if assert.NoError(t, err) {
		assert.NoError(t, checkBasicSFTP(client))
		client.Close()
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestMultiStepLoginCertAndPwd(t *testing.T) {
	u := getTestUser(true)
	u.Password = defaultPassword
	u.PublicKeys = []string{testCertValid, testCertOtherSourceAddress}
	u.Filters.DeniedLoginMethods = append(u.Filters.DeniedLoginMethods, []string{
		dataprovider.SSHLoginMethodKeyAndKeyboardInt,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}...)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	signer, err := getSignerForUserCert([]byte(testCertValid))
	assert.NoError(t, err)
	authMethods := []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.Password(defaultPassword),
	}
	client, err := getCustomAuthSftpClient(user, authMethods, "")
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	signer, err = getSignerForUserCert([]byte(testCertOtherSourceAddress))
	assert.NoError(t, err)
	authMethods = []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.Password(defaultPassword),
	}
	client, err = getCustomAuthSftpClient(user, authMethods, "")
	if !assert.Error(t, err) {
		client.Close()
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginUserStatus(t *testing.T) {
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, user.LastLogin, int64(0), "last login must be updated after a successful login: %v", user.LastLogin)
	}
	user.Status = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login for a disabled user must fail") {
		client.Close()
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginUserExpiration(t *testing.T) {
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, user.LastLogin, int64(0), "last login must be updated after a successful login: %v", user.LastLogin)
	}
	user.ExpirationDate = utils.GetTimeAsMsSinceEpoch(time.Now()) - 120000
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login for an expired user must fail") {
		client.Close()
	}
	user.ExpirationDate = utils.GetTimeAsMsSinceEpoch(time.Now()) + 120000
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginWithDatabaseCredentials(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.FsConfig.Provider = dataprovider.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "testbucket"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret(`{ "type": "service_account" }`)

	providerConf := config.GetProviderConf()
	providerConf.PreferDatabaseCredentials = true
	credentialsFile := filepath.Join(providerConf.CredentialsPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
	if !filepath.IsAbs(credentialsFile) {
		credentialsFile = filepath.Join(configDir, credentialsFile)
	}

	assert.NoError(t, dataprovider.Close())

	err := dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)

	if _, err = os.Stat(credentialsFile); err == nil {
		// remove the credentials file
		assert.NoError(t, os.Remove(credentialsFile))
	}

	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, kms.SecretStatusSecretBox, user.FsConfig.GCSConfig.Credentials.GetStatus())
	assert.NotEmpty(t, user.FsConfig.GCSConfig.Credentials.GetPayload())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetAdditionalData())
	assert.Empty(t, user.FsConfig.GCSConfig.Credentials.GetKey())

	assert.NoFileExists(t, credentialsFile)

	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	assert.NoError(t, dataprovider.Close())
	assert.NoError(t, config.LoadConfig(configDir, ""))
	providerConf = config.GetProviderConf()
	assert.NoError(t, dataprovider.Initialize(providerConf, configDir))
}

func TestLoginInvalidFs(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.FsConfig.Provider = dataprovider.GCSFilesystemProvider
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = kms.NewPlainSecret("invalid JSON for credentials")
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)

	providerConf := config.GetProviderConf()
	credentialsFile := filepath.Join(providerConf.CredentialsPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
	if !filepath.IsAbs(credentialsFile) {
		credentialsFile = filepath.Join(configDir, credentialsFile)
	}

	// now remove the credentials file so the filesystem creation will fail
	err = os.Remove(credentialsFile)
	assert.NoError(t, err)

	client, err := getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login must fail, the user has an invalid filesystem config") {
		client.Close()
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDeniedProtocols(t *testing.T) {
	u := getTestUser(true)
	u.Filters.DeniedProtocols = []string{common.ProtocolSSH}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, true)
	if !assert.Error(t, err, "SSH protocol is disabled, authentication must fail") {
		client.Close()
	}
	user.Filters.DeniedProtocols = []string{common.ProtocolFTP, common.ProtocolWebDAV}
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, true)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestDeniedLoginMethods(t *testing.T) {
	u := getTestUser(true)
	u.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPublicKey, dataprovider.LoginMethodPassword}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, true)
	if !assert.Error(t, err, "public key login is disabled, authentication must fail") {
		client.Close()
	}
	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodKeyboardInteractive, dataprovider.LoginMethodPassword}
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, true)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Password = defaultPassword
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	client, err = getSftpClient(user, false)
	if !assert.Error(t, err, "password login is disabled, authentication must fail") {
		client.Close()
	}
	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodKeyboardInteractive, dataprovider.SSHLoginMethodPublicKey}
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, false)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginWithIPFilters(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Filters.DeniedIP = []string{"192.167.0.0/24", "172.18.0.0/16"}
	u.Filters.AllowedIP = []string{}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Greater(t, user.LastLogin, int64(0), "last login must be updated after a successful login: %v", user.LastLogin)
	}
	user.Filters.AllowedIP = []string{"127.0.0.0/8"}
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Filters.AllowedIP = []string{"172.19.0.0/16"}
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login from an not allowed IP must fail") {
		client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginAfterUserUpdateEmptyPwd(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	user.Password = ""
	user.PublicKeys = []string{}
	// password and public key should remain unchanged
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginAfterUserUpdateEmptyPubKey(t *testing.T) {
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	user.Password = ""
	user.PublicKeys = []string{}
	// password and public key should remain unchanged
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestLoginKeyboardInteractiveAuth(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	user, _, err := httpd.AddUser(getTestUser(false), http.StatusOK)
	assert.NoError(t, err)
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), os.ModePerm)
	assert.NoError(t, err)
	client, err := getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Status = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the user is disabled") {
		client.Close()
	}
	user.Status = 1
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, -1), os.ModePerm)
	assert.NoError(t, err)
	client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the script returned -1") {
		client.Close()
	}
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, true, 1), os.ModePerm)
	assert.NoError(t, err)
	client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the script returned bad json") {
		client.Close()
	}
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 5, true, 1), os.ModePerm)
	assert.NoError(t, err)
	client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the script returned bad json") {
		client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
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
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(u, false), os.ModePerm)
	assert.NoError(t, err)
	providerConf.PreLoginHook = preLoginPath
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)

	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(user, true), os.ModePerm)
	assert.NoError(t, err)
	client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "pre-login script returned a non json response, login must fail") {
		client.Close()
	}
	user.Status = 0
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(user, false), os.ModePerm)
	assert.NoError(t, err)
	client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "pre-login script returned a disabled user, login must fail") {
		client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
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
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(u, false), os.ModePerm)
	assert.NoError(t, err)
	providerConf.PreLoginHook = preLoginPath
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)

	users, _, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(users))
	client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	users, _, err = httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	user := users[0]
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	err = os.Remove(preLoginPath)
	assert.NoError(t, err)
}

func TestPostConnectHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	common.Config.PostConnectHook = postConnectPath

	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = ioutil.WriteFile(postConnectPath, getPostConnectScriptContent(0), os.ModePerm)
	assert.NoError(t, err)
	client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}
	err = ioutil.WriteFile(postConnectPath, getPostConnectScriptContent(1), os.ModePerm)
	assert.NoError(t, err)
	client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err) {
		client.Close()
	}

	common.Config.PostConnectHook = "http://127.0.0.1:8080/api/v1/version"

	client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	common.Config.PostConnectHook = "http://127.0.0.1:8080/notfound"
	client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err) {
		client.Close()
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	err = ioutil.WriteFile(checkPwdPath, getCheckPwdScriptsContents(2, defaultPassword), os.ModePerm)
	assert.NoError(t, err)
	providerConf.CheckPasswordHook = checkPwdPath
	providerConf.CheckPasswordScope = 1
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)

	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		client.Close()
	}

	err = ioutil.WriteFile(checkPwdPath, getCheckPwdScriptsContents(0, defaultPassword), os.ModePerm)
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err) {
		client.Close()
	}

	err = ioutil.WriteFile(checkPwdPath, getCheckPwdScriptsContents(1, ""), os.ModePerm)
	assert.NoError(t, err)
	user.Password = defaultPassword + "1"
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	providerConf.CheckPasswordScope = 6
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	user, _, err = httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	user.Password = defaultPassword + "1"
	client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err) {
		client.Close()
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
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
	err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)

	testFileSize := int64(65535)
	client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
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
	client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "external auth login with invalid user must fail") {
		client.Close()
	}
	usePubKey = false
	u = getTestUser(usePubKey)
	u.PublicKeys = []string{}
	err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, ""), os.ModePerm)
	assert.NoError(t, err)
	client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	users, _, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	if assert.Equal(t, 1, len(users)) {
		user := users[0]
		assert.Equal(t, 0, len(user.PublicKeys))
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		assert.Equal(t, 1, user.UsedQuotaFiles)

		_, err = httpd.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
	}

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
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
	err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, extAuthUsername), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)

	// the user logins using "defaultUsername" and the external auth returns "extAuthUsername"
	testFileSize := int64(65535)
	client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
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
	client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
	}

	users, _, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(users))

	users, _, err = httpd.GetUsers(0, 0, extAuthUsername, http.StatusOK)
	assert.NoError(t, err)
	if assert.Equal(t, 1, len(users)) {
		user := users[0]
		assert.Equal(t, 0, len(user.PublicKeys))
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		assert.Equal(t, 1, user.UsedQuotaFiles)

		_, err = httpd.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)
	}

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	err = os.Remove(extAuthPath)
	assert.NoError(t, err)
}

func TestLoginExternalAuth(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	mappedPath := filepath.Join(os.TempDir(), "vdir1")
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
		err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, ""), os.ModePerm)
		assert.NoError(t, err)
		providerConf.ExternalAuthHook = extAuthPath
		providerConf.ExternalAuthScope = authScope
		err = dataprovider.Initialize(providerConf, configDir)
		assert.NoError(t, err)

		client, err := getSftpClient(u, usePubKey)
		if assert.NoError(t, err) {
			defer client.Close()
			assert.NoError(t, checkBasicSFTP(client))
		}
		u.Username = defaultUsername + "1"
		client, err = getSftpClient(u, usePubKey)
		if !assert.Error(t, err, "external auth login with invalid user must fail") {
			client.Close()
		}
		usePubKey = !usePubKey
		u = getTestUser(usePubKey)
		client, err = getSftpClient(u, usePubKey)
		if !assert.Error(t, err, "external auth login with valid user but invalid auth scope must fail") {
			client.Close()
		}
		users, _, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, users, 1) {
			user := users[0]
			if assert.Len(t, user.VirtualFolders, 1) {
				folder := user.VirtualFolders[0]
				assert.Equal(t, mappedPath, folder.MappedPath)
				assert.Equal(t, 1+authScope, folder.QuotaFiles)
				assert.Equal(t, 10+int64(authScope), folder.QuotaSize)
			}
			_, err = httpd.RemoveUser(user, http.StatusOK)
			assert.NoError(t, err)
			err = os.RemoveAll(user.GetHomeDir())
			assert.NoError(t, err)
		}

		_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath}, http.StatusOK)
		assert.NoError(t, err)
		err = dataprovider.Close()
		assert.NoError(t, err)
		err = config.LoadConfig(configDir, "")
		assert.NoError(t, err)
		providerConf = config.GetProviderConf()
		err = dataprovider.Initialize(providerConf, configDir)
		assert.NoError(t, err)
		err = os.Remove(extAuthPath)
		assert.NoError(t, err)
	}
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
	err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, false, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 4
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)

	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), os.ModePerm)
	assert.NoError(t, err)
	client, err := getKeyboardInteractiveSftpClient(u, []string{"1", "2"})
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	u.Username = defaultUsername + "1"
	client, err = getKeyboardInteractiveSftpClient(u, []string{"1", "2"})
	if !assert.Error(t, err, "external auth login with invalid user must fail") {
		client.Close()
	}
	usePubKey = true
	u = getTestUser(usePubKey)
	client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "external auth login with valid user but invalid auth scope must fail") {
		client.Close()
	}
	users, _, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	user := users[0]
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
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
	err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, true, ""), os.ModePerm)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)

	client, err := getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "login must fail, external auth returns a non json response") {
		client.Close()
	}

	usePubKey = false
	u = getTestUser(usePubKey)
	client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "login must fail, external auth returns a non json response") {
		client.Close()
	}
	users, _, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(users))

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
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
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
}

func TestMaxSessions(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Username += "1"
	u.MaxSessions = 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
		c, err := getSftpClient(user, usePubKey)
		if !assert.Error(t, err, "max sessions exceeded, new login should not succeed") {
			c.Close()
		}
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaFileReplace(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	testFileSize := int64(65535)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) { //nolint:dupl
		defer client.Close()
		expectedQuotaSize := user.UsedQuotaSize + testFileSize
		expectedQuotaFiles := user.UsedQuotaFiles + 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		// now replace the same file, the quota must not change
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		// now create a symlink, replace it with a file and check the quota
		// replacing a symlink is like uploading a new file
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		expectedQuotaFiles = expectedQuotaFiles + 1
		expectedQuotaSize = expectedQuotaSize + testFileSize
		err = sftpUploadFile(testFilePath, testFileName+".link", testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	}
	// now set a quota size restriction and upload the same file, upload should fail for space limit exceeded
	user.QuotaSize = testFileSize*2 - 1
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.Error(t, err, "quota size exceeded, file upload must fail")
		err = client.Remove(testFileName)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaRename(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	testFileSize := int64(65535)
	testFileSize1 := int64(65537)
	testFileName1 := "test_file1.dat" //nolint:goconst
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFilePath1 := filepath.Join(homeBasePath, testFileName1)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		err = client.Rename(testFileName1, testFileName+".rename")
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 4, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1*2, user.UsedQuotaSize)
		err = client.Rename(testDir, testDir+"1")
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 4, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1*2, user.UsedQuotaSize)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestQuotaScan(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	testFileSize := int64(65535)
	expectedQuotaSize := user.UsedQuotaSize + testFileSize
	expectedQuotaFiles := user.UsedQuotaFiles + 1
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	// create user with the same home dir, so there is at least an untracked file
	user, _, err = httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.StartQuotaScan(user, http.StatusAccepted)
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		scans, _, err := httpd.GetQuotaScans(http.StatusOK)
		if err == nil {
			return len(scans) == 0
		}
		return false
	}, 1*time.Second, 50*time.Millisecond)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	// test quota files
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = sftpUploadFile(testFilePath, testFileName+".quota", testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName+".quota.1", testFileSize, client)
		assert.Error(t, err, "user is over quota files, upload must fail")
		// rename should work
		err = client.Rename(testFileName+".quota", testFileName)
		assert.NoError(t, err)
	}
	// test quota size
	user.QuotaSize = testFileSize - 1
	user.QuotaFiles = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = sftpUploadFile(testFilePath, testFileName+".quota.1", testFileSize, client)
		assert.Error(t, err, "user is over quota size, upload must fail")
		err = client.Rename(testFileName, testFileName+".quota")
		assert.NoError(t, err)
		err = client.Rename(testFileName+".quota", testFileName)
		assert.NoError(t, err)
	}
	// now test quota limits while uploading the current file, we have 1 bytes remaining
	user.QuotaSize = testFileSize + 1
	user.QuotaFiles = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = sftpUploadFile(testFilePath1, testFileName1, testFileSize1, client)
		assert.Error(t, err)
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
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath1)
	assert.NoError(t, err)
	err = os.Remove(testFilePath2)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestUploadMaxSize(t *testing.T) {
	testFileSize := int64(65535)
	usePubKey := false
	u := getTestUser(usePubKey)
	u.Filters.MaxUploadFileSize = testFileSize + 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	testFileSize1 := int64(131072)
	testFileName1 := "test_file1.dat"
	testFilePath1 := filepath.Join(homeBasePath, testFileName1)
	err = createTestFile(testFilePath1, testFileSize1)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	wantedUploadElapsed := 1000 * (testFileSize / 1000) / u.UploadBandwidth
	wantedDownloadElapsed := 1000 * (testFileSize / 1000) / u.DownloadBandwidth
	// 100 ms tolerance
	wantedUploadElapsed -= 100
	wantedDownloadElapsed -= 100
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		assert.Eventually(t, func() bool { return len(common.Connections.GetStats()) == 0 }, 1*time.Second, 50*time.Millisecond)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestPatternsFilters(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFileSize := int64(131072)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName+".zip", testFileSize, client)
		assert.NoError(t, err)
	}
	user.Filters.FilePatterns = []dataprovider.PatternsFilter{
		{
			Path:            "/",
			AllowedPatterns: []string{"*.zIp"},
			DeniedPatterns:  []string{},
		},
	}
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.Remove(localDownloadPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

//nolint:dupl
func TestExtensionsFilters(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFileSize := int64(131072)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName+".zip", testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName+".jpg", testFileSize, client)
		assert.NoError(t, err)
	}
	user.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/",
			AllowedExtensions: []string{".zIp", ".jPg"},
			DeniedExtensions:  []string{},
		},
	}
	user.Filters.FilePatterns = []dataprovider.PatternsFilter{
		{
			Path:            "/",
			AllowedPatterns: []string{"*.jPg", "*.zIp"},
			DeniedPatterns:  []string{},
		},
	}
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		err = sftpDownloadFile(testFileName+".jpg", localDownloadPath, testFileSize, client)
		assert.NoError(t, err)
		err = client.Mkdir("dir.zip")
		assert.NoError(t, err)
		err = client.Rename("dir.zip", "dir1.zip")
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	vdirPath := "/vdir/subdir"
	testDir := "/userDir"
	testDir1 := "/userDir1"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
	})
	u.Permissions[testDir] = []string{dataprovider.PermCreateDirs}
	u.Permissions[testDir1] = []string{dataprovider.PermCreateDirs, dataprovider.PermUpload, dataprovider.PermDelete}
	u.Permissions[path.Join(testDir1, "subdir")] = []string{dataprovider.PermCreateSymlinks, dataprovider.PermUpload,
		dataprovider.PermDelete}

	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
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
		// we cannot create dirs inside /userDir1/subdir
		err = client.Rename("vdir2", testDir1)
		assert.Error(t, err)
		err = client.Rename("vdir2", "vdir3")
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath}, http.StatusOK)
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
	vdirPath1 := "/vdir1" //nolint:goconst
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2" //nolint:goconst
	u1.VirtualFolders = append(u1.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u1.VirtualFolders = append(u1.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u2.VirtualFolders = append(u2.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
		user, _, err := httpd.AddUser(u, http.StatusOK)
		assert.NoError(t, err)
		client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err) {
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
		_, err = httpd.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
		assert.NoError(t, err)
		_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
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

func TestTruncateQuotaLimits(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaSize = 20
	mappedPath := filepath.Join(os.TempDir(), "mapped")
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	vdirPath := "/vmapped"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
		QuotaFiles:  10,
	})
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		data := []byte("test data")
		f, err := client.OpenFile(testFileName, os.O_WRONLY)
		if assert.NoError(t, err) {
			n, err := f.Write(data)
			assert.NoError(t, err)
			assert.Equal(t, len(data), n)
			err = f.Truncate(2)
			assert.NoError(t, err)
			expectedQuotaFiles := 0
			expectedQuotaSize := int64(2)
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
			assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		}
		// now truncate by path
		err = client.Truncate(testFileName, 5)
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, int64(5), user.UsedQuotaSize)
		// now open an existing file without truncate it, quota should not change
		f, err = client.OpenFile(testFileName, os.O_WRONLY)
		if assert.NoError(t, err) {
			err = f.Close()
			assert.NoError(t, err)
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 1, user.UsedQuotaFiles)
			assert.Equal(t, int64(5), user.UsedQuotaSize)
		}
		// open the file truncating it
		f, err = client.OpenFile(testFileName, os.O_WRONLY|os.O_TRUNC)
		if assert.NoError(t, err) {
			err = f.Close()
			assert.NoError(t, err)
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 0, user.UsedQuotaFiles)
			assert.Equal(t, int64(0), user.UsedQuotaSize)
		}

		// basic test inside a virtual folder
		vfileName := path.Join(vdirPath, testFileName)
		f, err = client.OpenFile(vfileName, os.O_WRONLY)
		if assert.NoError(t, err) {
			n, err := f.Write(data)
			assert.NoError(t, err)
			assert.Equal(t, len(data), n)
			err = f.Truncate(2)
			assert.NoError(t, err)
			expectedQuotaFiles := 0
			expectedQuotaSize := int64(2)
			folder, _, err := httpd.GetFolders(0, 0, mappedPath, http.StatusOK)
			assert.NoError(t, err)
			if assert.Len(t, folder, 1) {
				fold := folder[0]
				assert.Equal(t, expectedQuotaSize, fold.UsedQuotaSize)
				assert.Equal(t, expectedQuotaFiles, fold.UsedQuotaFiles)
			}
			err = f.Close()
			assert.NoError(t, err)
			expectedQuotaFiles = 1
			folder, _, err = httpd.GetFolders(0, 0, mappedPath, http.StatusOK)
			assert.NoError(t, err)
			if assert.Len(t, folder, 1) {
				fold := folder[0]
				assert.Equal(t, expectedQuotaSize, fold.UsedQuotaSize)
				assert.Equal(t, expectedQuotaFiles, fold.UsedQuotaFiles)
			}
		}
		err = client.Truncate(vfileName, 1)
		assert.NoError(t, err)
		folder, _, err := httpd.GetFolders(0, 0, mappedPath, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			fold := folder[0]
			assert.Equal(t, int64(1), fold.UsedQuotaSize)
			assert.Equal(t, 1, fold.UsedQuotaFiles)
		}
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath}, http.StatusOK)
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
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	mappedPath3 := filepath.Join(os.TempDir(), "vdir3")
	vdirPath3 := "/vdir3"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  2,
		QuotaSize:   0,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  0,
		QuotaSize:   testFileSize + testFileSize1 + 1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath3}, http.StatusOK)
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
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2" //nolint:goconst
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		folder, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}

		err = client.Remove(path.Join(vdirPath1, testFileName))
		assert.NoError(t, err)
		err = client.Remove(path.Join(vdirPath2, testFileName))
		assert.NoError(t, err)

		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, int64(0), f.UsedQuotaSize)
			assert.Equal(t, 0, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, int64(0), f.UsedQuotaSize)
			assert.Equal(t, 0, f.UsedQuotaFiles)
		}
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
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
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		folder, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		// rename a file inside vdir2, it isn't included inside user quota, so we have:
		// - vdir1/dir1/testFileName.rename
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName.rename
		// - vdir2/dir2/testFileName1
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName), path.Join(vdirPath2, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		// rename a file inside vdir2 overwriting an existing, we now have:
		// - vdir1/dir1/testFileName.rename
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName.rename (initial testFileName1)
		err = client.Rename(path.Join(vdirPath2, dir2, testFileName1), path.Join(vdirPath2, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		// rename a file inside vdir1 overwriting an existing, we now have:
		// - vdir1/dir1/testFileName.rename (initial testFileName1)
		// - vdir2/dir1/testFileName.rename (initial testFileName1)
		err = client.Rename(path.Join(vdirPath1, dir2, testFileName1), path.Join(vdirPath1, dir1, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		// rename a directory inside the same virtual folder, quota should not change
		err = client.RemoveDirectory(path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.RemoveDirectory(path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirPath1, dir1), path.Join(vdirPath1, dir2))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirPath2, dir1), path.Join(vdirPath2, dir2))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
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
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		folder, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 3, f.UsedQuotaFiles)
		}
		// rename a file from vdir2 to vdir1, vdir2 is not included inside user quota, so we have:
		// - vdir1/dir1/testFileName
		// - vdir1/dir2/testFileName.rename
		// - vdir2/dir2/testFileName1
		// - vdir2/dir1/testFileName1.rename
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName), path.Join(vdirPath1, dir2, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize*2, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1*2, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		// rename a file from vdir1 to vdir2 overwriting an existing file, vdir1 is included inside user quota, so we have:
		// - vdir1/dir2/testFileName.rename
		// - vdir2/dir2/testFileName1 (is the initial testFileName)
		// - vdir2/dir1/testFileName1.rename
		err = client.Rename(path.Join(vdirPath1, dir1, testFileName), path.Join(vdirPath2, dir2, testFileName1))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1+testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		// rename a file from vdir2 to vdir1 overwriting an existing file, vdir2 is not included inside user quota, so we have:
		// - vdir1/dir2/testFileName.rename (is the initial testFileName1)
		// - vdir2/dir2/testFileName1 (is the initial testFileName)
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName1+".rename"), path.Join(vdirPath1, dir2, testFileName+".rename"))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}

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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 5, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1*3+testFileSize*2, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1*3+testFileSize*2, f.UsedQuotaSize)
			assert.Equal(t, 5, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, int64(0), f.UsedQuotaSize)
			assert.Equal(t, 0, f.UsedQuotaFiles)
		}
		// now move on vpath2
		err = client.Rename(path.Join(vdirPath1, dir2), path.Join(vdirPath2, dir1))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1*2+testFileSize, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1*2+testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 3, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
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
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		folder, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		// rename a file from vdir2 to the user home dir, vdir2 is not included in user quota so we have:
		// - testFileName
		// - testFileName1
		// - vdir1/dir2/testFileName1
		// - vdir2/dir1/testFileName
		err = client.Rename(path.Join(vdirPath2, dir2, testFileName1), path.Join(testFileName1))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1+testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		// rename a file from vdir1 to the user home dir overwriting an existing file, vdir1 is included in user quota so we have:
		// - testFileName (initial testFileName1)
		// - testFileName1
		// - vdir2/dir1/testFileName
		err = client.Rename(path.Join(vdirPath1, dir2, testFileName1), path.Join(testFileName))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1+testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, int64(0), f.UsedQuotaSize)
			assert.Equal(t, 0, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		// rename a file from vdir2 to the user home dir overwriting an existing file, vdir2 is not included in user quota so we have:
		// - testFileName (initial testFileName1)
		// - testFileName1 (initial testFileName)
		err = client.Rename(path.Join(vdirPath2, dir1, testFileName), path.Join(testFileName1))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, int64(0), f.UsedQuotaSize)
			assert.Equal(t, 0, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, int64(0), f.UsedQuotaSize)
			assert.Equal(t, 0, f.UsedQuotaFiles)
		}
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 6, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*3+testFileSize1*3, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, int64(0), f.UsedQuotaSize)
			assert.Equal(t, 0, f.UsedQuotaFiles)
		}
		// - testFileName (initial testFileName1)
		// - testFileName1 (initial testFileName)
		// - dir2/testFileName
		// - dir2/testFileName1
		// - dir1/testFileName
		// - dir1/testFileName1
		err = client.Rename(path.Join(vdirPath1, dir1), dir2)
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 6, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*3+testFileSize1*3, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, int64(0), f.UsedQuotaSize)
			assert.Equal(t, 0, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, int64(0), f.UsedQuotaSize)
			assert.Equal(t, 0, f.UsedQuotaFiles)
		}

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
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
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		folder, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		// rename a file from user home dir to vdir2, vdir2 is not included in user quota so we have:
		// - /vdir2/dir1/testFileName
		// - /vdir1/dir1/testFileName1
		err = client.Rename(testFileName, path.Join(vdirPath2, dir1, testFileName))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		// upload two new files to the user home dir so we have:
		// - testFileName
		// - testFileName1
		// - /vdir1/dir1/testFileName1
		// - /vdir2/dir1/testFileName
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath1, testFileName1, testFileSize1, client)
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1+testFileSize1, user.UsedQuotaSize)
		// rename a file from user home dir to vdir1 overwriting an existing file, vdir1 is included in user quota so we have:
		// - testFileName1
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName
		err = client.Rename(testFileName, path.Join(vdirPath1, dir1, testFileName1))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize+testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		// rename a file from user home dir to vdir2 overwriting an existing file, vdir2 is not included in user quota so we have:
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName (initial testFileName1)
		err = client.Rename(testFileName1, path.Join(vdirPath2, dir1, testFileName))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}

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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		// - /vdir1/adir/testFileName
		// - /vdir1/adir/testFileName1
		// - /vdir1/dir1/testFileName1 (initial testFileName)
		// - /vdir2/dir1/testFileName (initial testFileName1)
		err = client.Rename(dir1, path.Join(vdirPath1, "adir"))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize*2+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 3, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 3, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize*2+testFileSize1, user.UsedQuotaSize)
		folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize*2+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 3, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize1*2+testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 3, f.UsedQuotaFiles)
		}

		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath1)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
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
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestOverlappedMappedFolders(t *testing.T) {
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.TrackQuota = 0
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)

	usePubKey := false
	u := getTestUser(usePubKey)
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
	err = os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = checkBasicSFTP(client)
		assert.NoError(t, err)
		testFileSize := int64(131072)
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		fi, err := client.Stat(path.Join(vdirPath1, subDir, testFileName))
		if assert.NoError(t, err) {
			assert.Equal(t, testFileSize, fi.Size())
		}
		err = client.Rename(path.Join(vdirPath1, subDir, testFileName), path.Join(vdirPath2, testFileName+"1"))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirPath2, testFileName+"1"), path.Join(vdirPath1, subDir, testFileName))
		assert.NoError(t, err)
		err = client.Rename(path.Join(vdirPath1, subDir), path.Join(vdirPath2, subDir))
		assert.Error(t, err)
		err = client.Mkdir(subDir)
		assert.NoError(t, err)
		err = client.Rename(subDir, path.Join(vdirPath1, subDir))
		assert.Error(t, err)
		err = client.RemoveDirectory(path.Join(vdirPath1, subDir))
		assert.Error(t, err)
		err = client.Symlink(path.Join(vdirPath1, subDir), path.Join(vdirPath1, "adir"))
		assert.Error(t, err)
		err = client.Mkdir(path.Join(vdirPath1, subDir+"1"))
		assert.NoError(t, err)
		err = client.Symlink(path.Join(vdirPath1, subDir+"1"), path.Join(vdirPath1, subDir))
		assert.Error(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		_, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", path.Join(vdirPath1, subDir)), user, usePubKey)
		assert.Error(t, err)
	}

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)

	if providerConf.Driver != dataprovider.MemoryDataProviderName {
		client, err = getSftpClient(user, usePubKey)
		if !assert.Error(t, err) {
			client.Close()
		}

		_, err = httpd.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
		assert.NoError(t, err)
		_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
		assert.NoError(t, err)
	}

	_, _, err = httpd.AddUser(u, http.StatusOK)
	assert.Error(t, err)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestResolveOverlappedMappedPaths(t *testing.T) {
	u := getTestUser(false)
	mappedPath1 := filepath.Join(os.TempDir(), "mapped1", "subdir")
	vdirPath1 := "/vdir1/subdir"
	mappedPath2 := filepath.Join(os.TempDir(), "mapped2")
	vdirPath2 := "/vdir2/subdir"
	mappedPath3 := filepath.Join(os.TempDir(), "mapped1")
	vdirPath3 := "/vdir3"
	mappedPath4 := filepath.Join(os.TempDir(), "mapped1", "subdir", "vdir4")
	vdirPath4 := "/vdir4"
	u.VirtualFolders = []vfs.VirtualFolder{
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				MappedPath: mappedPath1,
			},
			VirtualPath: vdirPath1,
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				MappedPath: mappedPath2,
			},
			VirtualPath: vdirPath2,
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				MappedPath: mappedPath3,
			},
			VirtualPath: vdirPath3,
		},
		{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				MappedPath: mappedPath4,
			},
			VirtualPath: vdirPath4,
		},
	}
	err := os.MkdirAll(u.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath3, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath4, os.ModePerm)
	assert.NoError(t, err)

	fs := vfs.NewOsFs("", u.GetHomeDir(), u.VirtualFolders)
	p, err := fs.ResolvePath("/vdir1")
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(u.GetHomeDir(), "vdir1"), p)
	p, err = fs.ResolvePath("/vdir1/subdir")
	assert.NoError(t, err)
	assert.Equal(t, mappedPath1, p)
	p, err = fs.ResolvePath("/vdir3/subdir/vdir4/file.txt")
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(mappedPath4, "file.txt"), p)
	p, err = fs.ResolvePath("/vdir4/file.txt")
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(mappedPath4, "file.txt"), p)
	assert.Equal(t, filepath.Join(mappedPath3, "subdir", "vdir4", "file.txt"), p)
	assert.Equal(t, filepath.Join(mappedPath1, "vdir4", "file.txt"), p)
	p, err = fs.ResolvePath("/vdir3/subdir/vdir4/../file.txt")
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(mappedPath3, "subdir", "file.txt"), p)
	assert.Equal(t, filepath.Join(mappedPath1, "file.txt"), p)

	err = os.RemoveAll(u.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath4)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath3)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestVirtualFolderQuotaScan(t *testing.T) {
	mappedPath := filepath.Join(os.TempDir(), "mapped_dir")
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	testFileSize := int64(65535)
	testFilePath := filepath.Join(mappedPath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	expectedQuotaSize := testFileSize
	expectedQuotaFiles := 1
	folder, _, err := httpd.AddFolder(vfs.BaseVirtualFolder{
		MappedPath: mappedPath,
	}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.StartFolderQuotaScan(folder, http.StatusAccepted)
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		scans, _, err := httpd.GetFoldersQuotaScans(http.StatusOK)
		if err == nil {
			return len(scans) == 0
		}
		return false
	}, 1*time.Second, 50*time.Millisecond)
	folders, _, err := httpd.GetFolders(0, 0, mappedPath, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folders, 1) {
		folder = folders[0]
		assert.Equal(t, expectedQuotaFiles, folder.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, folder.UsedQuotaSize)
	}
	_, err = httpd.RemoveFolder(folder, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestVFolderMultipleQuotaScan(t *testing.T) {
	folderPath := filepath.Join(os.TempDir(), "folder_path")
	res := common.QuotaScans.AddVFolderQuotaScan(folderPath)
	assert.True(t, res)
	res = common.QuotaScans.AddVFolderQuotaScan(folderPath)
	assert.False(t, res)
	res = common.QuotaScans.RemoveVFolderQuotaScan(folderPath)
	assert.True(t, res)
	activeScans := common.QuotaScans.GetVFoldersQuotaScans()
	assert.Len(t, activeScans, 0)
	res = common.QuotaScans.RemoveVFolderQuotaScan(folderPath)
	assert.False(t, res)
}

func TestVFolderQuotaSize(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	testFileSize := int64(131072)
	u.QuotaFiles = 1
	u.QuotaSize = testFileSize + 1
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vpath1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vpath2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		// quota is included in the user's one
		QuotaFiles: -1,
		QuotaSize:  -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		// remove a file
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 0, user.UsedQuotaFiles)
		assert.Equal(t, int64(0), user.UsedQuotaSize)
		// upload to vdir1 must work now
		err = sftpUploadFile(testFilePath, path.Join(vdirPath1, testFileName), testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.UsedQuotaFiles)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)

		folder, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize, f.UsedQuotaSize)
			assert.Equal(t, 1, f.UsedQuotaFiles)
		}
	}
	// now create another user with the same shared folder but a different quota limit
	u.Username = defaultUsername + "1"
	u.VirtualFolders = nil
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  10,
		QuotaSize:   testFileSize*2 + 1,
	})
	user1, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err = getSftpClient(user1, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName+".quota"), testFileSize, client)
		assert.NoError(t, err)
		// the folder is now over quota for size but not for files
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName+".quota1"), testFileSize, client)
		assert.Error(t, err)
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)

	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		localDownloadPath := filepath.Join(homeBasePath, testDLFileName)
		err = sftpDownloadFile("missing_file", localDownloadPath, 0, client)
		assert.Error(t, err, "download missing file must fail")
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		err = client.Mkdir("test")
		assert.NoError(t, err)
		err = os.Chmod(user.GetHomeDir(), 0000)
		assert.NoError(t, err)
		_, err = client.Lstat(testFileName)
		assert.Error(t, err, "file stat must fail if we have no filesystem read permissions")
		err = os.Chmod(user.GetHomeDir(), os.ModePerm)
		assert.NoError(t, err)
		err = os.Chmod(filepath.Join(user.GetHomeDir(), "test"), 0000)
		assert.NoError(t, err)
		err = client.Rename(testFileName, path.Join("test", testFileName))
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = os.Chmod(filepath.Join(user.GetHomeDir(), "test"), os.ModePerm)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestOverwriteDirWithFile(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestHashedPasswords(t *testing.T) {
	usePubKey := false
	pwdMapping := make(map[string]string)
	pwdMapping["$pbkdf2-sha1$150000$DveVjgYUD05R$X6ydQZdyMeOvpgND2nqGR/0GGic="] = "password" //nolint:goconst
	pwdMapping["$pbkdf2-sha256$150000$E86a9YMX3zC7$R5J62hsSq+pYw00hLLPKBbcGXmq7fj5+/M0IFoYtZbo="] = "password"
	pwdMapping["$pbkdf2-sha512$150000$dsu7T5R3IaVQ$1hFXPO1ntRBcoWkSLKw+s4sAP09Xtu4Ya7CyxFq64jM9zdUg8eRJVr3NcR2vQgb0W9HHvZaILHsL4Q/Vr6arCg=="] = "password"
	pwdMapping["$1$b5caebda$VODr/nyhGWgZaY8sJ4x05."] = "password"
	pwdMapping["$2a$14$ajq8Q7fbtFRQvXpdCq7Jcuy.Rx1h/L4J60Otx.gyNLbAYctGMJ9tK"] = "secret"
	pwdMapping["$6$459ead56b72e44bc$uog86fUxscjt28BZxqFBE2pp2QD8P/1e98MNF75Z9xJfQvOckZnQ/1YJqiq1XeytPuDieHZvDAMoP7352ELkO1"] = "secret"
	pwdMapping["$apr1$OBWLeSme$WoJbB736e7kKxMBIAqilb1"] = "password"

	for pwd, clearPwd := range pwdMapping {
		u := getTestUser(usePubKey)
		u.Password = pwd
		user, _, err := httpd.AddUser(u, http.StatusOK)
		assert.NoError(t, err)
		user.Password = clearPwd
		client, err := getSftpClient(user, usePubKey)
		if assert.NoError(t, err, "unable to login with password %#v", pwd) {
			defer client.Close()
			assert.NoError(t, checkBasicSFTP(client))
		}
		user.Password = pwd
		client, err = getSftpClient(user, usePubKey)
		if !assert.Error(t, err, "login with wrong password must fail") {
			client.Close()
		}
		_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	user.Password = pbkdf2ClearPwd
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Password = pbkdf2Pwd
	client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login with wrong password must fail") {
		client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileName+".rename")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		_, err = client.Stat(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Remove(testFileName)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = client.Mkdir("testdir")
		assert.Error(t, err, "mkdir without permission should not succeed")
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSubDirsUploads(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermChtimes, dataprovider.PermDownload, dataprovider.PermOverwrite}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Symlink(testFileName, testFileNameSub+".link")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileNameSub+".rename")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
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
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Remove(testFileName + ".rename")
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSubDirsOverwrite(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermOverwrite, dataprovider.PermListItems}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSubDirsDownloads(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermChmod, dataprovider.PermUpload, dataprovider.PermListItems}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Chtimes(testFileName, time.Now(), time.Now())
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Rename(testFileName, testFileName+".rename")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Symlink(testFileName, testFileName+".link")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Remove(testFileName)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Chtimes("subdir/", time.Now(), time.Now())
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Chtimes(testFileName, time.Now(), time.Now())
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestOpenUnhandledChannel(t *testing.T) {
	u := getTestUser(false)
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.RemoveDirectory("/subdir/dir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Mkdir("/subdir/otherdir/dir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Mkdir("/otherdir")
		assert.NoError(t, err)
		err = client.Mkdir("/subdir/otherdir")
		assert.NoError(t, err)
		err = client.Rename("/otherdir", "/subdir/otherdir/adir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Symlink("/otherdir", "/subdir/otherdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Symlink("/otherdir", "/otherdir_link")
		assert.NoError(t, err)
		err = client.Rename("/otherdir", "/otherdir1")
		assert.NoError(t, err)
		err = client.RemoveDirectory("/otherdir1")
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRootDirCommands(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = client.Rename("/", "rootdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.Symlink("/", "rootdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
		err = client.RemoveDirectory("/")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		}
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestRelativePaths(t *testing.T) {
	user := getTestUser(true)
	var path, rel string
	filesystems := []vfs.Fs{vfs.NewOsFs("", user.GetHomeDir(), user.VirtualFolders)}
	keyPrefix := strings.TrimPrefix(user.GetHomeDir(), "/") + "/"
	s3config := vfs.S3FsConfig{
		KeyPrefix: keyPrefix,
	}
	s3fs, _ := vfs.NewS3Fs("", user.GetHomeDir(), s3config)
	gcsConfig := vfs.GCSFsConfig{
		KeyPrefix: keyPrefix,
	}
	gcsfs, _ := vfs.NewGCSFs("", user.GetHomeDir(), gcsConfig)
	if runtime.GOOS != osWindows {
		filesystems = append(filesystems, s3fs, gcsfs)
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
	filesystems := []vfs.Fs{vfs.NewOsFs("", user.GetHomeDir(), user.VirtualFolders)}
	keyPrefix := strings.TrimPrefix(user.GetHomeDir(), "/") + "/"
	s3config := vfs.S3FsConfig{
		KeyPrefix: keyPrefix,
		Bucket:    "bucket",
		Region:    "us-east-1",
	}
	err = os.MkdirAll(user.GetHomeDir(), os.ModePerm)
	assert.NoError(t, err)
	s3fs, err := vfs.NewS3Fs("", user.GetHomeDir(), s3config)
	assert.NoError(t, err)
	gcsConfig := vfs.GCSFsConfig{
		KeyPrefix: keyPrefix,
	}
	gcsfs, _ := vfs.NewGCSFs("", user.GetHomeDir(), gcsConfig)
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
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	vdirPath := "/vdir" //nolint:goconst
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	fs := vfs.NewOsFs("", user.GetHomeDir(), user.VirtualFolders)
	rel := fs.GetRelativePath(mappedPath)
	assert.Equal(t, vdirPath, rel)
	rel = fs.GetRelativePath(filepath.Join(mappedPath, ".."))
	assert.Equal(t, "/", rel)
	// path outside home and virtual dir
	rel = fs.GetRelativePath(filepath.Join(mappedPath, "../vdir1"))
	assert.Equal(t, "/", rel)
	rel = fs.GetRelativePath(filepath.Join(mappedPath, "../vdir/file.txt"))
	assert.Equal(t, "/vdir/file.txt", rel)
	rel = fs.GetRelativePath(filepath.Join(user.HomeDir, "vdir1/file.txt"))
	assert.Equal(t, "/vdir1/file.txt", rel)
}

func TestResolveVirtualPaths(t *testing.T) {
	user := getTestUser(true)
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	vdirPath := "/vdir"
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	osFs := vfs.NewOsFs("", user.GetHomeDir(), user.VirtualFolders).(*vfs.OsFs)
	b, f := osFs.GetFsPaths("/vdir/a.txt")
	assert.Equal(t, mappedPath, b)
	assert.Equal(t, filepath.Join(mappedPath, "a.txt"), f)
	b, f = osFs.GetFsPaths("/vdir/sub with space & spécial chars/a.txt")
	assert.Equal(t, mappedPath, b)
	assert.Equal(t, filepath.Join(mappedPath, "sub with space & spécial chars/a.txt"), f)
	b, f = osFs.GetFsPaths("/vdir/../a.txt")
	assert.Equal(t, user.GetHomeDir(), b)
	assert.Equal(t, filepath.Join(user.GetHomeDir(), "a.txt"), f)
	b, f = osFs.GetFsPaths("/vdir1/a.txt")
	assert.Equal(t, user.GetHomeDir(), b)
	assert.Equal(t, filepath.Join(user.GetHomeDir(), "/vdir1/a.txt"), f)
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

//nolint:dupl
func TestFilterFilePatterns(t *testing.T) {
	user := getTestUser(true)
	pattern := dataprovider.PatternsFilter{
		Path:            "/test",
		AllowedPatterns: []string{"*.jpg", "*.png"},
		DeniedPatterns:  []string{"*.pdf"},
	}
	filters := dataprovider.UserFilters{
		FilePatterns: []dataprovider.PatternsFilter{pattern},
	}
	user.Filters = filters
	assert.True(t, user.IsFileAllowed("/test/test.jPg"))
	assert.False(t, user.IsFileAllowed("/test/test.pdf"))
	assert.True(t, user.IsFileAllowed("/test.pDf"))

	filters.FilePatterns = append(filters.FilePatterns, dataprovider.PatternsFilter{
		Path:            "/",
		AllowedPatterns: []string{"*.zip", "*.rar", "*.pdf"},
		DeniedPatterns:  []string{"*.gz"},
	})
	user.Filters = filters
	assert.False(t, user.IsFileAllowed("/test1/test.gz"))
	assert.True(t, user.IsFileAllowed("/test1/test.zip"))
	assert.False(t, user.IsFileAllowed("/test/sub/test.pdf"))
	assert.False(t, user.IsFileAllowed("/test1/test.png"))

	filters.FilePatterns = append(filters.FilePatterns, dataprovider.PatternsFilter{
		Path:           "/test/sub",
		DeniedPatterns: []string{"*.tar"},
	})
	user.Filters = filters
	assert.False(t, user.IsFileAllowed("/test/sub/sub/test.tar"))
	assert.True(t, user.IsFileAllowed("/test/sub/test.gz"))
	assert.False(t, user.IsFileAllowed("/test/test.zip"))
}

//nolint:dupl
func TestFilterFileExtensions(t *testing.T) {
	user := getTestUser(true)
	extension := dataprovider.ExtensionsFilter{
		Path:              "/test",
		AllowedExtensions: []string{".jpg", ".png"},
		DeniedExtensions:  []string{".pdf"},
	}
	filters := dataprovider.UserFilters{
		FileExtensions: []dataprovider.ExtensionsFilter{extension},
	}
	user.Filters = filters
	assert.True(t, user.IsFileAllowed("/test/test.jPg"))
	assert.False(t, user.IsFileAllowed("/test/test.pdf"))
	assert.True(t, user.IsFileAllowed("/test.pDf"))

	filters.FileExtensions = append(filters.FileExtensions, dataprovider.ExtensionsFilter{
		Path:              "/",
		AllowedExtensions: []string{".zip", ".rar", ".pdf"},
		DeniedExtensions:  []string{".gz"},
	})
	user.Filters = filters
	assert.False(t, user.IsFileAllowed("/test1/test.gz"))
	assert.True(t, user.IsFileAllowed("/test1/test.zip"))
	assert.False(t, user.IsFileAllowed("/test/sub/test.pdf"))
	assert.False(t, user.IsFileAllowed("/test1/test.png"))

	filters.FileExtensions = append(filters.FileExtensions, dataprovider.ExtensionsFilter{
		Path:             "/test/sub",
		DeniedExtensions: []string{".tar"},
	})
	user.Filters = filters
	assert.False(t, user.IsFileAllowed("/test/sub/sub/test.tar"))
	assert.True(t, user.IsFileAllowed("/test/sub/test.gz"))
	assert.False(t, user.IsFileAllowed("/test/test.zip"))
}

func TestUserAllowedLoginMethods(t *testing.T) {
	user := getTestUser(true)
	user.Filters.DeniedLoginMethods = dataprovider.ValidSSHLoginMethods
	allowedMethods := user.GetAllowedLoginMethods()
	assert.Equal(t, 0, len(allowedMethods))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	allowedMethods = user.GetAllowedLoginMethods()
	assert.Equal(t, 2, len(allowedMethods))

	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyAndKeyboardInt, allowedMethods))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyAndPassword, allowedMethods))
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
	assert.True(t, utils.IsStringInSlice(dataprovider.LoginMethodPassword, methods))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, methods))
	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPublicKey}, false)
	assert.Equal(t, 1, len(methods))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, methods))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
		dataprovider.SSHLoginMethodKeyAndKeyboardInt,
	}
	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPublicKey}, true)
	assert.Equal(t, 1, len(methods))
	assert.True(t, utils.IsStringInSlice(dataprovider.LoginMethodPassword, methods))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
		dataprovider.SSHLoginMethodKeyAndPassword,
	}
	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPublicKey}, true)
	assert.Equal(t, 1, len(methods))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, methods))
}

func TestUserIsLoginMethodAllowed(t *testing.T) {
	user := getTestUser(true)
	user.Filters.DeniedLoginMethods = []string{
		dataprovider.LoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	assert.False(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, nil))
	assert.False(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodPublicKey, nil))
	assert.False(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodKeyboardInteractive, nil))
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, []string{dataprovider.SSHLoginMethodPublicKey}))
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodKeyboardInteractive, []string{dataprovider.SSHLoginMethodPublicKey}))
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodKeyAndPassword, []string{dataprovider.SSHLoginMethodPublicKey}))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.LoginMethodPassword, nil))
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

func TestSSHCommands(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
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

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSSHFileHash(t *testing.T) {
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		user.Permissions = make(map[string][]string)
		user.Permissions["/"] = []string{dataprovider.PermUpload}
		_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
		assert.NoError(t, err)
		_, err = runSSHCommand("sha512sum "+testFileName, user, usePubKey)
		assert.Error(t, err, "hash command with no list permission must fail")

		user.Permissions["/"] = []string{dataprovider.PermAny}
		_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSSHCopy(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vdir1/subdir"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2/subdir"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  100,
		QuotaSize:   0,
	})
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:             "/",
			DeniedExtensions: []string{".denied"},
		},
	}
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testDir := "adir"
	testDir1 := "adir1"
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 4, user.UsedQuotaFiles)
		assert.Equal(t, 2*testFileSize+2*testFileSize1, user.UsedQuotaSize)
		folder, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, testFileSize+testFileSize1, f.UsedQuotaSize)
			assert.Equal(t, 2, f.UsedQuotaFiles)
		}

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
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 7, user.UsedQuotaFiles)
			assert.Equal(t, 4*testFileSize+3*testFileSize1, user.UsedQuotaSize)
			folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
			assert.NoError(t, err)
			if assert.Len(t, folder, 1) {
				f := folder[0]
				assert.Equal(t, testFileSize*2+testFileSize1*2, f.UsedQuotaSize)
				assert.Equal(t, 4, f.UsedQuotaFiles)
			}
		}
		out, err = runSSHCommand(fmt.Sprintf("sftpgo-copy %v %v", path.Join(vdirPath1, testDir1), path.Join(vdirPath1, testDir1+"copy")),
			user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
			_, err := client.Stat(path.Join(vdirPath2, testDir1+"copy"))
			assert.NoError(t, err)
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 9, user.UsedQuotaFiles)
			assert.Equal(t, 5*testFileSize+4*testFileSize1, user.UsedQuotaSize)
			folder, _, err = httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
			assert.NoError(t, err)
			if assert.Len(t, folder, 1) {
				f := folder[0]
				assert.Equal(t, 2*testFileSize+2*testFileSize1, f.UsedQuotaSize)
				assert.Equal(t, 4, f.UsedQuotaFiles)
			}
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath2,
		},
		VirtualPath: vdirPath2,
		QuotaFiles:  3,
		QuotaSize:   testFileSize + testFileSize1 + 1,
	})
	u.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:             "/",
			DeniedExtensions: []string{".denied"},
		},
	}
	err := os.MkdirAll(mappedPath1, os.ModePerm)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, 0, user.UsedQuotaFiles)
		assert.Equal(t, int64(0), user.UsedQuotaSize)
		folder, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, 0, f.UsedQuotaFiles)
			assert.Equal(t, int64(0), f.UsedQuotaSize)
		}
		folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
		assert.NoError(t, err)
		if assert.Len(t, folder, 1) {
			f := folder[0]
			assert.Equal(t, 0, f.UsedQuotaFiles)
			assert.Equal(t, int64(0), f.UsedQuotaSize)
		}
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
		user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
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

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath2)
	assert.NoError(t, err)
}

func TestSSHRemove(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vdir1/sub"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2/sub"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
			assert.NoError(t, err)
			assert.Equal(t, 3, user.UsedQuotaFiles)
			assert.Equal(t, testFileSize+2*testFileSize1, user.UsedQuotaSize)
		}
		out, err = runSSHCommand(fmt.Sprintf("sftpgo-remove %v", path.Join(vdirPath1, testDir)), user, usePubKey)
		if assert.NoError(t, err) {
			assert.Equal(t, "OK\n", string(out))
			_, err := client.Stat(path.Join(vdirPath1, testFileName))
			assert.Error(t, err)
			user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		_, err = runSSHCommand("sftpgo-remove adir", user, usePubKey)
		assert.Error(t, err)
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)

	out, err = pushToGitRepo(clonePath)
	if !assert.NoError(t, err, "unexpected error, out: %v", string(out)) {
		printLatestLogs(10)
	}

	out, err = addFileToGitRepo(clonePath, 131072)
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	user.QuotaSize = user.UsedQuotaSize + 1
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
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

	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: "/" + repoName,
		QuotaFiles:  0,
		QuotaSize:   0,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		// we upload a file so the user is over quota
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

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath}, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	repoName := "testrepo"
	clonePath := filepath.Join(homeBasePath, repoName)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(filepath.Join(homeBasePath, repoName))
	assert.NoError(t, err)
	out, err := cloneGitRepo(homeBasePath, "/"+repoName, user.Username)
	assert.Error(t, err, "cloning a missing repo must fail, out: %v", string(out))

	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(131074)
	expectedQuotaSize := user.UsedQuotaSize + testFileSize
	expectedQuotaFiles := user.UsedQuotaFiles + 1
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
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
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)

	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestSCPUploadFileOverwrite(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(32760)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	assert.NoError(t, err)
	// test a new upload that must overwrite the existing file
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
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
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, testFileSize, user.UsedQuotaSize)
		assert.Equal(t, 1, user.UsedQuotaFiles)
	}
	err = scpUpload(testFilePath, remoteUpPath+".link", true, false)
	assert.NoError(t, err)
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, testFileSize*2, user.UsedQuotaSize)
	assert.Equal(t, 2, user.UsedQuotaFiles)

	err = os.Remove(localPath)
	assert.NoError(t, err)
	err = os.Remove(testFilePath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPRecursive(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
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

	err = os.RemoveAll(testBaseDirPath)
	assert.NoError(t, err)
	err = os.RemoveAll(testBaseDirDownPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPExtensionsFilter(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	user.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/",
			AllowedExtensions: []string{".zip"},
			DeniedExtensions:  []string{},
		},
	}
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
	assert.NoError(t, err)
	err = scpDownload(localPath, remoteDownPath, false, false)
	assert.Error(t, err, "scp download must fail")
	err = scpUpload(testFilePath, remoteUpPath, false, false)
	assert.Error(t, err, "scp upload must fail")

	_, err = httpd.RemoveUser(user, http.StatusOK)
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

func TestSCPUploadMaxSize(t *testing.T) {
	testFileSize := int64(65535)
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Filters.MaxUploadFileSize = testFileSize + 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	vdirPath := "/vdir"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath,
		},
		VirtualPath: vdirPath,
	})
	err := os.MkdirAll(mappedPath, os.ModePerm)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
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

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath}, http.StatusOK)
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

func TestSCPVirtualFoldersQuota(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
			MappedPath: mappedPath1,
		},
		VirtualPath: vdirPath1,
		QuotaFiles:  -1,
		QuotaSize:   -1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		BaseVirtualFolder: vfs.BaseVirtualFolder{
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
	assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	folder, _, err := httpd.GetFolders(0, 0, mappedPath1, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folder, 1) {
		f := folder[0]
		assert.Equal(t, expectedQuotaSize, f.UsedQuotaSize)
		assert.Equal(t, expectedQuotaFiles, f.UsedQuotaFiles)
	}
	folder, _, err = httpd.GetFolders(0, 0, mappedPath2, http.StatusOK)
	assert.NoError(t, err)
	if assert.Len(t, folder, 1) {
		f := folder[0]
		assert.Equal(t, expectedQuotaSize, f.UsedQuotaSize)
		assert.Equal(t, expectedQuotaFiles, f.UsedQuotaFiles)
	}

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath1}, http.StatusOK)
	assert.NoError(t, err)
	_, err = httpd.RemoveFolder(vfs.BaseVirtualFolder{MappedPath: mappedPath2}, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPPermCreateDirs(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPPermUpload(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermDownload, dataprovider.PermCreateDirs}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPPermOverwrite(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPPermDownload(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermUpload, dataprovider.PermCreateDirs}
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	user, _, err = httpd.UpdateUser(user, http.StatusOK, "")
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPEscapeHomeDir(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPUploadPaths(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPOverwriteDirWithFile(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	u := getTestUser(usePubKey)
	u.Username += "1"
	u.HomeDir += "1"
	user1, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user1.GetHomeDir())
	assert.NoError(t, err)
	_, err = httpd.RemoveUser(user1, http.StatusOK)
	assert.NoError(t, err)
}

func TestSCPErrors(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	u := getTestUser(true)
	user, _, err := httpd.AddUser(u, http.StatusOK)
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
	_, _, err = httpd.UpdateUser(user, http.StatusOK, "")
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
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
}

// End SCP tests

func waitTCPListening(address string) {
	for {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			logger.WarnToConsole("tcp server %v not listening: %v\n", address, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		logger.InfoToConsole("tcp server %v now listening\n", address)
		conn.Close()
		break
	}
}

func getTestUser(usePubKey bool) dataprovider.User {
	user := dataprovider.User{
		Username:       defaultUsername,
		Password:       defaultPassword,
		HomeDir:        filepath.Join(homeBasePath, defaultUsername),
		Status:         1,
		ExpirationDate: 0,
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = allPerms
	if usePubKey {
		user.PublicKeys = []string{testPubKey}
		user.Password = ""
	}
	return user
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

func getSftpClientWithAddr(user dataprovider.User, usePubKey bool, addr string) (*sftp.Client, error) {
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
			return nil, err
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		if len(user.Password) > 0 {
			config.Auth = []ssh.AuthMethod{ssh.Password(user.Password)}
		} else {
			config.Auth = []ssh.AuthMethod{ssh.Password(defaultPassword)}
		}
	}
	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return sftpClient, err
	}
	sftpClient, err = sftp.NewClient(conn)
	return sftpClient, err
}

func getSftpClient(user dataprovider.User, usePubKey bool) (*sftp.Client, error) {
	return getSftpClientWithAddr(user, usePubKey, sftpServerAddr)
}

func getKeyboardInteractiveSftpClient(user dataprovider.User, answers []string) (*sftp.Client, error) {
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
		return sftpClient, err
	}
	sftpClient, err = sftp.NewClient(conn)
	return sftpClient, err
}

func getCustomAuthSftpClient(user dataprovider.User, authMethods []ssh.AuthMethod, addr string) (*sftp.Client, error) {
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
		return sftpClient, err
	}
	sftpClient, err = sftp.NewClient(conn)
	return sftpClient, err
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
	return ioutil.WriteFile(path, content, os.ModePerm)
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
	// we need to close the file to trigger the close method on server
	// we cannot defer closing or Lstat will fail for uploads in atomic mode
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

func sftpUploadResumeFile(localSourcePath string, remoteDestPath string, expectedSize int64, invalidOffset bool,
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
	// we need to close the file to trigger the close method on server
	// we cannot defer closing or Lstat will fail for upload atomic mode
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
	c := make(chan error)
	go func() {
		c <- sftpUploadFile(localSourcePath, remoteDestPath, expectedSize, client)
	}()
	return c
}

func sftpDownloadNonBlocking(remoteSourcePath string, localDestPath string, expectedSize int64, client *sftp.Client) <-chan error {
	c := make(chan error)
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

func getExtAuthScriptContent(user dataprovider.User, nonJSONResponse bool, username string) []byte {
	extAuthContent := []byte("#!/bin/sh\n\n")
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

func getPostConnectScriptContent(exitCode int) []byte {
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
