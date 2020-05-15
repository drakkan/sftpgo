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
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"github.com/pkg/sftp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/config"
	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpd"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/sftpd"
	"github.com/drakkan/sftpgo/utils"
	"github.com/drakkan/sftpgo/vfs"
)

const (
	logSender       = "sftpdTesting"
	sftpServerAddr  = "127.0.0.1:2022"
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
	testCertExpired       = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgU3TLP5285k20fBSsdZioI78oJUpaRXFlgx5IPg6gWg8AAAADAQABAAABgQC03jj0D+djk7pxIf/0OhrxrchJTRZklofJ1NoIu4752Sq02mdXmarMVsqJ1cAjV5LBVy3D1F5U6XW4rppkXeVtd04Pxb09ehtH0pRRPaoHHlALiJt8CoMpbKYMA8b3KXPPriGxgGomvtU2T2RMURSwOZbMtpsugfjYSWenyYX+VORYhylWnSXL961LTyC21ehd6d6QnW9G7E5hYMITMY9TuQZz3bROYzXiTsgN0+g6Hn7exFQp50p45StUMfV/SftCMdCxlxuyGny2CrN/vfjO7xxOo2uv7q1qm10Q46KPWJQv+pgZ/OfL+EDjy07n5QVSKHlbx+2nT4Q0EgOSQaCTYwn3YjtABfIxWwgAFdyj6YlPulCL22qU4MYhDcA6PSBwDdf8hvxBfvsiHdM+JcSHvv8/VeJhk6CmnZxGY0fxBupov27z3yEO8nAg8k+6PaUiW1MSUfuGMF/ktB8LOstXsEPXSszuyXiOv4DaryOXUiSn7bmRqKcEFlJusO6aZP0AAAAAAAAABAAAAAEAAAAOdGVzdF91c2VyX3NmdHAAAAASAAAADnRlc3RfdXNlcl9zZnRwAAAAAEs93LgAAAAATR8QOAAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDF5fcwZHiyixmnE6IlOZJpZhWXoh62gN+yadAA0GJ509SAEaZVLPDP8S5RsE8mUikR3wxynVshxHeqMhrkS+RlNbhSlOXDdNg94yTrq/xF8Z/PgKRInvef74k5i7bAIytza7jERzFJ/ujTEy3537T5k5EYQJ15ZQGuvzynSdv+6o99SjI4jFplyQOZ2QcYbEAmhHm5GgQlIiEFG/RlDtLksOulKZxOY3qPzP0AyQxtZJXn/5vG40aW9LTbwxCJqWlgrkFXMqAAVCbuU5YspwhiXmKt1PsldiXw23oloa4caCKN1jzbFiGuZNXEU2Ebx7JIvjQCPaUYwLjEbkRDxDqN/vmwZqBuKYiuG9Eafx+nFSQkr7QYb5b+mT+/1IFHnmeRGn38731kBqtH7tpzC/t+soRX9p2HtJM+9MYhblO2OqTSPGTlxihWUkyiRBekpAhaiHld16TsG+A3bOJHrojGcX+5g6oGarKGLAMcykL1X+rZqT993Mo6d2Z7q43MOXEAAAGUAAAADHJzYS1zaGEyLTUxMgAAAYAlH3hhj8J6xLyVpeLZjblzwDKrxp/MWiH30hQ965ExPrPRcoAZFEKVqOYdj6bp4Q19Q4Yzqdobg3aN5ym2iH0b2TlOY0mM901CAoHbNJyiLs+0KiFRoJ+30EDj/hcKusg6v8ln2yixPagAyQu3zyiWo4t1ZuO3I86xchGlptStxSdHAHPFCfpbhcnzWFZctiMqUutl82C4ROWyjOZcRzdVdWHeN5h8wnooXuvba2VkT8QPmjYYyRGuQ3Hg+ySdh8Tel4wiix1Dg5MX7Wjh4hKEx80No9UPy+0iyZMNc07lsWAtrY6NRxGM5CzB6mklscB8TzFrVSnIl9u3bquLfaCrFt/Mft5dR7Yy4jmF+zUhjia6h6giCZ91J+FZ4hV+WkBtPCvTfrGWoA1BgEB/iI2xOq/NPqJ7UXRoMXk/l0NPgRPT2JS1adegqnt4ddr6IlmPyZxaSEvXhanjKdfMlEFYO1wz7ouqpYUozQVy4KXBlzFlNwyD1hI+k4+/A6AIYeI= nicola@p1"
	configDir             = ".."
	permissionErrorString = "Permission Denied"
	osWindows             = "windows"
)

var (
	allPerms         = []string{dataprovider.PermAny}
	homeBasePath     string
	scpPath          string
	gitPath          string
	sshPath          string
	pubKeyPath       string
	privateKeyPath   string
	trustedCAUserKey string
	gitWrapPath      string
	extAuthPath      string
	keyIntAuthPath   string
	preLoginPath     string
	logFilePath      string
)

func TestMain(m *testing.M) {
	logFilePath = filepath.Join(configDir, "sftpgo_sftpd_test.log")
	loginBannerFileName := "login_banner"
	loginBannerFile := filepath.Join(configDir, loginBannerFileName)
	logger.InitLogger(logFilePath, 5, 1, 28, false, zerolog.DebugLevel)
	err := ioutil.WriteFile(loginBannerFile, []byte("simple login banner\n"), 0777)
	if err != nil {
		logger.WarnToConsole("error creating login banner: %v", err)
		os.Exit(1)
	}
	err = config.LoadConfig(configDir, "")
	if err != nil {
		logger.WarnToConsole("error loading configuration: %v", err)
		os.Exit(1)
	}
	providerConf := config.GetProviderConf()

	err = dataprovider.Initialize(providerConf, configDir)
	if err != nil {
		logger.WarnToConsole("error initializing data provider: %v", err)
		os.Exit(1)
	}

	httpConfig := config.GetHTTPConfig()
	httpConfig.Initialize(configDir)

	dataProvider := dataprovider.GetProvider()
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
	// we run the test cases with UploadMode atomic and resume support. The non atomic code path
	// simply does not execute some code so if it works in atomic mode will
	// work in non atomic mode too
	sftpdConf.UploadMode = 2
	homeBasePath = os.TempDir()
	var scriptArgs string
	if runtime.GOOS == osWindows {
		scriptArgs = "%*"
	} else {
		sftpdConf.Actions.ExecuteOn = []string{"download", "upload", "rename", "delete", "ssh_cmd"}
		sftpdConf.Actions.Command = "/bin/true"
		sftpdConf.Actions.HTTPNotificationURL = "http://127.0.0.1:8083/"
		scriptArgs = "$@"
		scpPath, err = exec.LookPath("scp")
		if err != nil {
			logger.Warn(logSender, "", "unable to get scp command. SCP tests will be skipped, err: %v", err)
			logger.WarnToConsole("unable to get scp command. SCP tests will be skipped, err: %v", err)
			scpPath = ""
		}
	}
	checkGitCommand()

	keyIntAuthPath = filepath.Join(homeBasePath, "keyintauth.sh")
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), 0755)
	if err != nil {
		logger.WarnToConsole("error writing keyboard interactive script: %v", err)
		os.Exit(1)
	}
	sftpdConf.KeyboardInteractiveHook = keyIntAuthPath

	pubKeyPath = filepath.Join(homeBasePath, "ssh_key.pub")
	privateKeyPath = filepath.Join(homeBasePath, "ssh_key")
	trustedCAUserKey = filepath.Join(homeBasePath, "ca_user_key")
	gitWrapPath = filepath.Join(homeBasePath, "gitwrap.sh")
	extAuthPath = filepath.Join(homeBasePath, "extauth.sh")
	preLoginPath = filepath.Join(homeBasePath, "prelogin.sh")
	err = ioutil.WriteFile(pubKeyPath, []byte(testPubKey+"\n"), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save public key to file: %v", err)
	}
	err = ioutil.WriteFile(privateKeyPath, []byte(testPrivateKey+"\n"), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save private key to file: %v", err)
	}
	err = ioutil.WriteFile(gitWrapPath, []byte(fmt.Sprintf("%v -i %v -oStrictHostKeyChecking=no %v\n",
		sshPath, privateKeyPath, scriptArgs)), 0755)
	if err != nil {
		logger.WarnToConsole("unable to save gitwrap shell script: %v", err)
	}
	err = ioutil.WriteFile(trustedCAUserKey, []byte(testCAUserKey), 0600)
	if err != nil {
		logger.WarnToConsole("unable to save trusted CA user key: %v", err)
	}
	sftpdConf.TrustedUserCAKeys = append(sftpdConf.TrustedUserCAKeys, trustedCAUserKey)
	sftpd.SetDataProvider(dataProvider)
	httpd.SetDataProvider(dataProvider)

	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.Error(logSender, "", "could not start SFTP server: %v", err)
		}
	}()

	go func() {
		if err := httpdConf.Initialize(configDir, false); err != nil {
			logger.Error(logSender, "", "could not start HTTP server: %v", err)
		}
	}()

	waitTCPListening(fmt.Sprintf("%s:%d", sftpdConf.BindAddress, sftpdConf.BindPort))
	waitTCPListening(fmt.Sprintf("%s:%d", httpdConf.BindAddress, httpdConf.BindPort))

	sftpdConf.BindPort = 2222
	sftpdConf.ProxyProtocol = 1
	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.Error(logSender, "", "could not start SFTP server: %v", err)
		}
	}()

	waitTCPListening(fmt.Sprintf("%s:%d", sftpdConf.BindAddress, sftpdConf.BindPort))

	sftpdConf.BindPort = 2224
	sftpdConf.ProxyProtocol = 2
	go func() {
		logger.Debug(logSender, "", "initializing SFTP server with config %+v", sftpdConf)
		if err := sftpdConf.Initialize(configDir); err != nil {
			logger.Error(logSender, "", "could not start SFTP server: %v", err)
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
	os.Remove(keyIntAuthPath)
	os.Exit(exitCode)
}

func TestInitialization(t *testing.T) {
	err := config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	sftpdConf := config.GetSFTPDConfig()
	sftpdConf.Umask = "invalid umask"
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
	sftpdConf.ProxyProtocol = 1
	sftpdConf.ProxyAllowed = []string{"1270.0.0.1"}
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.Keys = []sftpd.Key{
		{
			PrivateKey: "missing file",
		},
	}
	err = sftpdConf.Initialize(configDir)
	assert.Error(t, err)
	sftpdConf.Keys = nil
	sftpdConf.TrustedUserCAKeys = []string{"missing file"}
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
		testFileName := "test_file.dat" //nolint:goconst
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
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
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
}

func TestProxyProtocol(t *testing.T) {
	usePubKey := false
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	// remove the home dir to test auto creation
	err = os.RemoveAll(user.HomeDir)
	assert.NoError(t, err)
	client, err := getSftpClientWithAddr(user, usePubKey, "127.0.0.1:2222")
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
		testFileName := "test_file.dat"
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
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize+appendDataSize, client)
		assert.NoError(t, err)
		initialHash, err := computeHashForFile(sha256.New(), testFilePath)
		assert.NoError(t, err)
		donwloadedFileHash, err := computeHashForFile(sha256.New(), localDownloadPath)
		assert.NoError(t, err)
		assert.Equal(t, initialHash, donwloadedFileHash)
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
		testFileName := "/test_file.dat"
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
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		_, err = client.ReadLink(testFileName + ".link")
		assert.Error(t, err, "readlink is currently not implemented so must fail")
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
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		_, err := client.Lstat(testFileName)
		assert.NoError(t, err)
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
		assert.NoError(t, err)
		assert.Equal(t, newPerm, newFi.Mode().Perm())
		_, err = client.ReadLink(testFileName)
		assert.Error(t, err, "readlink is not supported and must fail")
		err = client.Truncate(testFileName, 0)
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
		testFileName := "test_file.dat"
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
		testFileName := "test_file.dat"
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
		testFileName := "test_file.dat"
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
		testFileName := "test_file.dat"
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
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	client, err = getSftpClient(user, true)
	if !assert.Error(t, err, "login with invalid public key must fail") {
		defer client.Close()
	}
	// login a user with multiple public keys, only the second one is valid
	user.PublicKeys = []string{testPubKey1, testPubKey}
	user.Password = ""
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	client, err := getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)})
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	// try login using a cert signed from an untrusted CA
	signer, err = getSignerForUserCert([]byte(testCertUntrustedCA))
	assert.NoError(t, err)
	client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)})
	if !assert.Error(t, err) {
		client.Close()
	}
	// try login using an host certificate instead of an user certificate
	signer, err = getSignerForUserCert([]byte(testHostCert))
	assert.NoError(t, err)
	client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)})
	if !assert.Error(t, err) {
		client.Close()
	}
	// try login using a user certificate with an authorized source address different from localhost
	signer, err = getSignerForUserCert([]byte(testCertOtherSourceAddress))
	assert.NoError(t, err)
	client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)})
	if !assert.Error(t, err) {
		client.Close()
	}
	// try login using an expired certificate
	signer, err = getSignerForUserCert([]byte(testCertExpired))
	assert.NoError(t, err)
	client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)})
	if !assert.Error(t, err) {
		client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	// now login with a username not in the set of valid principals for given certificate
	u.Username += "1"
	user, _, err = httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)

	signer, err = getSignerForUserCert([]byte(testCertValid))
	assert.NoError(t, err)
	client, err = getCustomAuthSftpClient(user, []ssh.AuthMethod{ssh.PublicKeys(signer)})
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
		dataprovider.SSHLoginMethodPassword,
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
	client, err = getCustomAuthSftpClient(user, authMethods)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	authMethods = []ssh.AuthMethod{
		ssh.Password(defaultPassword),
		ssh.PublicKeys(signer),
	}
	_, err = getCustomAuthSftpClient(user, authMethods)
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
		dataprovider.SSHLoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}...)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), 0755)
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
	client, err = getCustomAuthSftpClient(user, authMethods)
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
	_, err = getCustomAuthSftpClient(user, authMethods)
	assert.Error(t, err, "multi step auth login with wrong order must fail")

	authMethods = []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.Password(defaultPassword),
	}
	_, err = getCustomAuthSftpClient(user, authMethods)
	assert.Error(t, err, "multi step auth login with wrong method must fail")

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
		dataprovider.SSHLoginMethodPassword,
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
	client, err := getCustomAuthSftpClient(user, authMethods)
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
	client, err = getCustomAuthSftpClient(user, authMethods)
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
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if !assert.Error(t, err, "login for an expired user must fail") {
		client.Close()
	}
	user.ExpirationDate = utils.GetTimeAsMsSinceEpoch(time.Now()) + 120000
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
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

func TestLoginInvalidFs(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.FsConfig.Provider = 2
	u.FsConfig.GCSConfig.Bucket = "test"
	u.FsConfig.GCSConfig.Credentials = base64.StdEncoding.EncodeToString([]byte("invalid JSON for credentials"))
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	// now remove the credentials file so the filesystem creation will fail
	providerConf := config.GetProviderConf()
	credentialsFile := filepath.Join(providerConf.CredentialsPath, fmt.Sprintf("%v_gcs_credentials.json", u.Username))
	if !filepath.IsAbs(credentialsFile) {
		credentialsFile = filepath.Join(configDir, credentialsFile)
	}
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

func TestDeniedLoginMethods(t *testing.T) {
	u := getTestUser(true)
	u.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodPublicKey, dataprovider.SSHLoginMethodPassword}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, true)
	if !assert.Error(t, err, "public key login is disabled, authentication must fail") {
		client.Close()
	}
	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodKeyboardInteractive, dataprovider.SSHLoginMethodPassword}
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	client, err = getSftpClient(user, true)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Password = defaultPassword
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)

	client, err = getSftpClient(user, false)
	if !assert.Error(t, err, "password login is disabled, authentication must fail") {
		client.Close()
	}
	user.Filters.DeniedLoginMethods = []string{dataprovider.SSHLoginMethodKeyboardInteractive, dataprovider.SSHLoginMethodPublicKey}
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Filters.AllowedIP = []string{"172.19.0.0/16"}
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), 0755)
	assert.NoError(t, err)
	client, err := getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	user.Status = 0
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the user is disabled") {
		client.Close()
	}
	user.Status = 1
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, -1), 0755)
	assert.NoError(t, err)
	client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the script returned -1") {
		client.Close()
	}
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, true, 1), 0755)
	assert.NoError(t, err)
	client, err = getKeyboardInteractiveSftpClient(user, []string{"1", "2"})
	if !assert.Error(t, err, "keyboard interactive auth must fail the script returned bad json") {
		client.Close()
	}
	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 5, true, 1), 0755)
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
	dataProvider := dataprovider.GetProvider()
	err := dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(u, false), 0755)
	assert.NoError(t, err)
	providerConf.PreLoginHook = preLoginPath
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())

	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(user, true), 0755)
	assert.NoError(t, err)
	client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "pre-login script returned a non json response, login must fail") {
		client.Close()
	}
	user.Status = 0
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(user, false), 0755)
	assert.NoError(t, err)
	client, err = getSftpClient(u, usePubKey)
	if !assert.Error(t, err, "pre-login script returned a disabled user, login must fail") {
		client.Close()
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	dataProvider = dataprovider.GetProvider()
	err = dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	err = os.Remove(preLoginPath)
	assert.NoError(t, err)
}

func TestPreLoginUserCreation(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := false
	u := getTestUser(usePubKey)
	dataProvider := dataprovider.GetProvider()
	err := dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = ioutil.WriteFile(preLoginPath, getPreLoginScriptContent(u, false), 0755)
	assert.NoError(t, err)
	providerConf.PreLoginHook = preLoginPath
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())

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
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	dataProvider = dataprovider.GetProvider()
	err = dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	err = os.Remove(preLoginPath)
	assert.NoError(t, err)
}

func TestLoginExternalAuthPwdAndPubKey(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1000
	dataProvider := dataprovider.GetProvider()
	err := dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, false), 0755)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())

	testFileSize := int64(65535)
	client, err := getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		testFileName := "test_file.dat"
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
	err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, false), 0755)
	assert.NoError(t, err)
	client, err = getSftpClient(u, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		assert.NoError(t, checkBasicSFTP(client))
	}
	users, _, err := httpd.GetUsers(0, 0, defaultUsername, http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))
	user := users[0]
	assert.Equal(t, 0, len(user.PublicKeys))
	assert.Equal(t, testFileSize, user.UsedQuotaSize)
	assert.Equal(t, 1, user.UsedQuotaFiles)

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	dataProvider = dataprovider.GetProvider()
	err = dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	err = os.Remove(extAuthPath)
	assert.NoError(t, err)
}

func TestLoginExternalAuth(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	extAuthScopes := []int{1, 2}
	for _, authScope := range extAuthScopes {
		var usePubKey bool
		if authScope == 1 {
			usePubKey = false
		} else {
			usePubKey = true
		}
		u := getTestUser(usePubKey)
		dataProvider := dataprovider.GetProvider()
		err := dataprovider.Close(dataProvider)
		assert.NoError(t, err)
		err = config.LoadConfig(configDir, "")
		assert.NoError(t, err)
		providerConf := config.GetProviderConf()
		err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, false), 0755)
		assert.NoError(t, err)
		providerConf.ExternalAuthHook = extAuthPath
		providerConf.ExternalAuthScope = authScope
		err = dataprovider.Initialize(providerConf, configDir)
		assert.NoError(t, err)
		httpd.SetDataProvider(dataprovider.GetProvider())
		sftpd.SetDataProvider(dataprovider.GetProvider())

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
		assert.Equal(t, 1, len(users))

		user := users[0]
		_, err = httpd.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		err = os.RemoveAll(user.GetHomeDir())
		assert.NoError(t, err)

		dataProvider = dataprovider.GetProvider()
		err = dataprovider.Close(dataProvider)
		assert.NoError(t, err)
		err = config.LoadConfig(configDir, "")
		assert.NoError(t, err)
		providerConf = config.GetProviderConf()
		err = dataprovider.Initialize(providerConf, configDir)
		assert.NoError(t, err)
		httpd.SetDataProvider(dataprovider.GetProvider())
		sftpd.SetDataProvider(dataprovider.GetProvider())
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
	dataProvider := dataprovider.GetProvider()
	err := dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, false), 0755)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 4
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())

	err = ioutil.WriteFile(keyIntAuthPath, getKeyboardInteractiveScriptContent([]string{"1", "2"}, 0, false, 1), 0755)
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

	dataProvider = dataprovider.GetProvider()
	err = dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	err = os.Remove(extAuthPath)
	assert.NoError(t, err)
}

func TestLoginExternalAuthErrors(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	dataProvider := dataprovider.GetProvider()
	err := dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	err = ioutil.WriteFile(extAuthPath, getExtAuthScriptContent(u, true), 0755)
	assert.NoError(t, err)
	providerConf.ExternalAuthHook = extAuthPath
	providerConf.ExternalAuthScope = 0
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())

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

	dataProvider = dataprovider.GetProvider()
	err = dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	err = os.Remove(extAuthPath)
	assert.NoError(t, err)
}

func TestQuotaDisabledError(t *testing.T) {
	dataProvider := dataprovider.GetProvider()
	err := dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf := config.GetProviderConf()
	providerConf.TrackQuota = 0
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 10
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)

	dataProvider = dataprovider.GetProvider()
	err = dataprovider.Close(dataProvider)
	assert.NoError(t, err)
	err = config.LoadConfig(configDir, "")
	assert.NoError(t, err)
	providerConf = config.GetProviderConf()
	err = dataprovider.Initialize(providerConf, configDir)
	assert.NoError(t, err)
	httpd.SetDataProvider(dataprovider.GetProvider())
	sftpd.SetDataProvider(dataprovider.GetProvider())
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
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		expectedQuotaSize := user.UsedQuotaSize + testFileSize
		expectedQuotaFiles := user.UsedQuotaFiles + 1
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		// now replace the same file, the quota must not change
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	}
	// now set a quota size restriction and upload the same file, upload should fail for space limit exceeded
	user.QuotaSize = testFileSize - 1
	user, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	client, err = getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
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
		testFileName := "test_file.dat"
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
	_, err = httpd.StartQuotaScan(user, http.StatusCreated)
	assert.NoError(t, err)
	err = waitQuotaScans()
	assert.NoError(t, err)
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
	res := sftpd.AddQuotaScan(defaultUsername)
	assert.True(t, res)
	res = sftpd.AddQuotaScan(defaultUsername)
	assert.False(t, res, "add quota must fail if another scan is already active")
	err := sftpd.RemoveQuotaScan(defaultUsername)
	assert.NoError(t, err)
	activeScans := sftpd.GetQuotaScans()
	assert.Equal(t, 0, len(activeScans))
}

func TestQuotaSize(t *testing.T) {
	usePubKey := false
	testFileSize := int64(65535)
	u := getTestUser(usePubKey)
	u.QuotaFiles = 1
	u.QuotaSize = testFileSize - 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName+".quota", testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName+".quota.1", testFileSize, client)
		assert.Error(t, err, "user is over quota file upload must fail")
		err = client.Remove(testFileName + ".quota")
		assert.NoError(t, err)
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
}

func TestBandwidthAndConnections(t *testing.T) {
	usePubKey := false
	testFileSize := int64(131072)
	u := getTestUser(usePubKey)
	u.UploadBandwidth = 30
	u.DownloadBandwidth = 25
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
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		startTime := time.Now()
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		elapsed := time.Since(startTime).Nanoseconds() / 1000000
		assert.GreaterOrEqual(t, elapsed, wantedUploadElapsed, "upload bandwidth throttling not respected")
		startTime = time.Now()
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
		c := sftpDownloadNonBlocking(testFileName, localDownloadPath, testFileSize, client)
		waitForActiveTransfer()
		// wait some additional arbitrary time to wait for transfer activity to happen
		// it is need to reach all the code in CheckIdleConnections
		time.Sleep(100 * time.Millisecond)
		sftpd.CheckIdleConnections()
		err = <-c
		assert.NoError(t, err)
		elapsed = time.Since(startTime).Nanoseconds() / 1000000
		assert.GreaterOrEqual(t, elapsed, wantedDownloadElapsed, "download bandwidth throttling not respected")
		// test disconnection
		c = sftpUploadNonBlocking(testFilePath, testFileName+"_partial", testFileSize, client)
		waitForActiveTransfer()
		time.Sleep(100 * time.Millisecond)
		sftpd.CheckIdleConnections()
		stats := sftpd.GetConnectionsStats()
		for _, stat := range stats {
			sftpd.CloseActiveConnection(stat.ConnectionID)
		}
		err = <-c
		assert.Error(t, err, "connection closed while uploading: the upload must fail")
		waitForNoActiveTransfer()
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

func TestExtensionsFilters(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFileSize := int64(131072)
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
	}
	user.Filters.FileExtensions = []dataprovider.ExtensionsFilter{
		{
			Path:              "/",
			AllowedExtensions: []string{".zip"},
			DeniedExtensions:  []string{},
		},
	}
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
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
	vdirPath := "/vdir" //nolint:goconst
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: vdirPath,
		MappedPath:  mappedPath,
	})
	err := os.MkdirAll(mappedPath, 0777)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		testFileSize := int64(131072)
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
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
		err = os.Remove(testFilePath)
		assert.NoError(t, err)
		err = os.Remove(localDownloadPath)
		assert.NoError(t, err)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath)
	assert.NoError(t, err)
}

func TestVirtualFoldersQuota(t *testing.T) {
	usePubKey := false
	u := getTestUser(usePubKey)
	u.QuotaFiles = 100
	mappedPath1 := filepath.Join(os.TempDir(), "vdir1")
	vdirPath1 := "/vdir1"
	mappedPath2 := filepath.Join(os.TempDir(), "vdir2")
	vdirPath2 := "/vdir2"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: vdirPath1,
		MappedPath:  mappedPath1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath:      vdirPath2,
		MappedPath:       mappedPath2,
		ExcludeFromQuota: true,
	})
	err := os.MkdirAll(mappedPath1, 0777)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, 0777)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		testFileName := "test_file.dat"
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
		err = sftpUploadFile(testFilePath, path.Join(vdirPath2, testFileName), testFileSize, client)
		assert.NoError(t, err)
		expectedQuotaFiles := 2
		expectedQuotaSize := testFileSize * 2
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
		err = client.Remove(path.Join(vdirPath2, testFileName))
		assert.NoError(t, err)
		user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
		assert.NoError(t, err)
		assert.Equal(t, expectedQuotaFiles, user.UsedQuotaFiles)
		assert.Equal(t, expectedQuotaSize, user.UsedQuotaSize)
	}
	_, err = httpd.RemoveUser(user, http.StatusOK)
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
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
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
		err = os.Chmod(user.GetHomeDir(), 0755)
		assert.NoError(t, err)
		testFileSize := int64(65535)
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(user.GetHomeDir(), testFileName)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		_, err = client.Stat(testFileName)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
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
		err = os.Chmod(user.GetHomeDir(), 0755)
		assert.NoError(t, err)
		err = os.Chmod(filepath.Join(user.GetHomeDir(), "test"), 0000)
		assert.NoError(t, err)
		err = client.Rename(testFileName, path.Join("test", testFileName))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), sftp.ErrSSHFxPermissionDenied.Error())
		err = os.Chmod(filepath.Join(user.GetHomeDir(), "test"), 0755)
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
		testFileName := "test_file.dat"
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
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		_, err = client.ReadDir(".")
		assert.Error(t, err, "read remote dir without permission should not succeed")
		_, err = client.Stat("test_file")
		assert.Error(t, err, "stat remote file without permission should not succeed")
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
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
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
		testFileName := "test_file.dat"
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
		testFileName := "test_file.dat"
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
		testFileName := "test_file.dat"
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
	u.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDownload, dataprovider.PermUpload, dataprovider.PermDelete,
		dataprovider.PermCreateDirs, dataprovider.PermCreateSymlinks, dataprovider.PermOverwrite, dataprovider.PermChmod,
		dataprovider.PermChown, dataprovider.PermChtimes}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileName+".rename")
		assert.Error(t, err, "rename without permission should not succeed")
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
		testFileName := "test_file.dat"
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
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = client.Chmod(testFileName, 0666)
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
		testFileName := "test_file.dat"
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
		testFileName := "test_file.dat"
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
	u.Permissions["/subdir"] = []string{dataprovider.PermChtimes, dataprovider.PermDownload}
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	client, err := getSftpClient(user, usePubKey)
	if assert.NoError(t, err) {
		defer client.Close()
		err = client.Mkdir("subdir")
		assert.NoError(t, err)
		testFileName := "test_file.dat"
		testFileNameSub := "/subdir/test_file_dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileNameSub, testFileSize, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Symlink(testFileName, testFileNameSub+".link")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Symlink(testFileName, testFileName+".link")
		assert.NoError(t, err)
		err = client.Rename(testFileName, testFileNameSub+".rename")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Rename(testFileName, testFileName+".rename")
		assert.NoError(t, err)
		err = client.Remove(testFileNameSub)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
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
			assert.Contains(t, err.Error(), permissionErrorString)
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
		localDownloadPath := filepath.Join(homeBasePath, "test_download.dat")
		err = sftpDownloadFile(testFileName, localDownloadPath, testFileSize, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Chtimes(testFileName, time.Now(), time.Now())
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Rename(testFileName, testFileName+".rename")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Symlink(testFileName, testFileName+".link")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Remove(testFileName)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
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
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Chtimes("subdir/", time.Now(), time.Now())
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
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

func TestPermsSubDirsCommands(t *testing.T) {
	usePubKey := true
	u := getTestUser(usePubKey)
	u.Permissions["/"] = []string{dataprovider.PermAny}
	u.Permissions["/subdir"] = []string{dataprovider.PermDownload, dataprovider.PermUpload}
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
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.RemoveDirectory("/subdir/dir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Mkdir("/subdir/dir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Mkdir("/otherdir")
		assert.NoError(t, err)
		err = client.Rename("/otherdir", "/subdir/otherdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Symlink("/otherdir", "/subdir/otherdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Symlink("/otherdir", "/otherdir_link")
		assert.NoError(t, err)
		err = client.Rename("/otherdir", "/otherdir1")
		assert.NoError(t, err)
		err = client.RemoveDirectory("/subdir")
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
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.Symlink("/", "rootdir")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
		}
		err = client.RemoveDirectory("/")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), permissionErrorString)
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
	err = os.MkdirAll(user.GetHomeDir(), 0777)
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
	vdirPath := "/vdir"
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: vdirPath,
		MappedPath:  mappedPath,
	})
	err := os.MkdirAll(mappedPath, 0777)
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
		VirtualPath: vdirPath,
		MappedPath:  mappedPath,
	})
	err := os.MkdirAll(mappedPath, 0777)
	assert.NoError(t, err)
	osFs := vfs.NewOsFs("", user.GetHomeDir(), user.VirtualFolders).(vfs.OsFs)
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

func TestVirtualFoldersExcludeQuota(t *testing.T) {
	user := getTestUser(true)
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	vdirPath := "/vdir/sub"
	vSubDirPath := path.Join(vdirPath, "subdir", "subdir")
	vSubDir1Path := path.Join(vSubDirPath, "subdir", "subdir")
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		VirtualPath:      vdirPath,
		MappedPath:       mappedPath,
		ExcludeFromQuota: false,
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		VirtualPath:      vSubDir1Path,
		MappedPath:       mappedPath,
		ExcludeFromQuota: false,
	})
	user.VirtualFolders = append(user.VirtualFolders, vfs.VirtualFolder{
		VirtualPath:      vSubDirPath,
		MappedPath:       mappedPath,
		ExcludeFromQuota: true,
	})

	assert.False(t, user.IsFileExcludedFromQuota("/file"))
	assert.False(t, user.IsFileExcludedFromQuota(path.Join(vdirPath, "file")))
	assert.True(t, user.IsFileExcludedFromQuota(path.Join(vSubDirPath, "file")))
	assert.True(t, user.IsFileExcludedFromQuota(path.Join(vSubDir1Path, "..", "file")))
	assert.False(t, user.IsFileExcludedFromQuota(path.Join(vSubDir1Path, "file")))
	assert.False(t, user.IsFileExcludedFromQuota(path.Join(vSubDirPath, "..", "file")))
	// we check the parent dir for a file
	assert.False(t, user.IsFileExcludedFromQuota(vSubDirPath))
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
		dataprovider.SSHLoginMethodPassword,
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
		dataprovider.SSHLoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	assert.False(t, user.IsPartialAuth(dataprovider.SSHLoginMethodPassword))
	assert.False(t, user.IsPartialAuth(dataprovider.SSHLoginMethodKeyboardInteractive))
	assert.True(t, user.IsPartialAuth(dataprovider.SSHLoginMethodPublicKey))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.SSHLoginMethodPassword,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	assert.False(t, user.IsPartialAuth(dataprovider.SSHLoginMethodPublicKey))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.SSHLoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
	}
	assert.False(t, user.IsPartialAuth(dataprovider.SSHLoginMethodPublicKey))
}

func TestUserGetNextAuthMethods(t *testing.T) {
	user := getTestUser(true)
	user.Filters.DeniedLoginMethods = []string{
		dataprovider.SSHLoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	methods := user.GetNextAuthMethods(nil)
	assert.Equal(t, 0, len(methods))

	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPassword})
	assert.Equal(t, 0, len(methods))

	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodKeyboardInteractive})
	assert.Equal(t, 0, len(methods))

	methods = user.GetNextAuthMethods([]string{
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	})
	assert.Equal(t, 0, len(methods))

	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPublicKey})
	assert.Equal(t, 2, len(methods))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodPassword, methods))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, methods))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.SSHLoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
		dataprovider.SSHLoginMethodKeyAndKeyboardInt,
	}
	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPublicKey})
	assert.Equal(t, 1, len(methods))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodPassword, methods))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.SSHLoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
		dataprovider.SSHLoginMethodKeyAndPassword,
	}
	methods = user.GetNextAuthMethods([]string{dataprovider.SSHLoginMethodPublicKey})
	assert.Equal(t, 1, len(methods))
	assert.True(t, utils.IsStringInSlice(dataprovider.SSHLoginMethodKeyboardInteractive, methods))
}

func TestUserIsLoginMethodAllowed(t *testing.T) {
	user := getTestUser(true)
	user.Filters.DeniedLoginMethods = []string{
		dataprovider.SSHLoginMethodPassword,
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	assert.False(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodPassword, nil))
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodPassword, []string{dataprovider.SSHLoginMethodPublicKey}))
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodKeyboardInteractive, []string{dataprovider.SSHLoginMethodPublicKey}))

	user.Filters.DeniedLoginMethods = []string{
		dataprovider.SSHLoginMethodPublicKey,
		dataprovider.SSHLoginMethodKeyboardInteractive,
	}
	assert.True(t, user.IsLoginMethodAllowed(dataprovider.SSHLoginMethodPassword, nil))
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
		testFileName := "test_file.dat"
		testFilePath := filepath.Join(homeBasePath, testFileName)
		testFileSize := int64(65535)
		err = createTestFile(testFilePath, testFileSize)
		assert.NoError(t, err)
		err = sftpUploadFile(testFilePath, testFileName, testFileSize, client)
		assert.NoError(t, err)
		user.Permissions = make(map[string][]string)
		user.Permissions["/"] = []string{dataprovider.PermUpload}
		_, _, err = httpd.UpdateUser(user, http.StatusOK)
		assert.NoError(t, err)
		_, err = runSSHCommand("sha512sum "+testFileName, user, usePubKey)
		assert.Error(t, err, "hash command with no list permission must fail")

		user.Permissions["/"] = []string{dataprovider.PermAny}
		_, _, err = httpd.UpdateUser(user, http.StatusOK)
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

func TestBasicGitCommands(t *testing.T) {
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
	out, err := initGitRepo(filepath.Join(user.HomeDir, repoName))
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	out, err = cloneGitRepo(homeBasePath, "/"+repoName, user.Username)
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	out, err = addFileToGitRepo(clonePath, 128)
	assert.NoError(t, err, "unexpected error, out: %v", string(out))

	user.QuotaFiles = 100000
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)

	out, err = pushToGitRepo(clonePath)
	if !assert.NoError(t, err, "unexpected error, out: %v", string(out)) {
		printLatestLogs(10)
	}

	err = waitQuotaScans()
	assert.NoError(t, err)

	user, _, err = httpd.GetUserByID(user.ID, http.StatusOK)
	assert.NoError(t, err)
	user.QuotaSize = user.UsedQuotaSize - 1
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	out, err = pushToGitRepo(clonePath)
	assert.Error(t, err, "git push must fail if quota is exceeded, out: %v", string(out))

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)

	err = os.RemoveAll(user.GetHomeDir())
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
	testFileName := "test_file.dat"
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
	testFileName := "test_file.dat"
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
	testFileName := "test_file.dat"
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
	testFileName := "test_file.dat"
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
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
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

func TestSCPVirtualFolders(t *testing.T) {
	if len(scpPath) == 0 {
		t.Skip("scp command not found, unable to execute this test")
	}
	usePubKey := true
	u := getTestUser(usePubKey)
	mappedPath := filepath.Join(os.TempDir(), "vdir")
	vdirPath := "/vdir"
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath: vdirPath,
		MappedPath:  mappedPath,
	})
	err := os.MkdirAll(mappedPath, 0777)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFileName := "test_file.dat"
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
	remoteDownPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", vdirPath))
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, vdirPath)
	err = scpUpload(testBaseDirPath, remoteUpPath, true, false)
	assert.NoError(t, err)
	err = scpDownload(testBaseDirDownPath, remoteDownPath, true, true)
	assert.NoError(t, err)

	_, err = httpd.RemoveUser(user, http.StatusOK)
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
		VirtualPath: vdirPath1,
		MappedPath:  mappedPath1,
	})
	u.VirtualFolders = append(u.VirtualFolders, vfs.VirtualFolder{
		VirtualPath:      vdirPath2,
		MappedPath:       mappedPath2,
		ExcludeFromQuota: true,
	})
	err := os.MkdirAll(mappedPath1, 0777)
	assert.NoError(t, err)
	err = os.MkdirAll(mappedPath2, 0777)
	assert.NoError(t, err)
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFileName := "test_file.dat"
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

	_, err = httpd.RemoveUser(user, http.StatusOK)
	assert.NoError(t, err)
	err = os.RemoveAll(testBaseDirPath)
	assert.NoError(t, err)
	err = os.RemoveAll(testBaseDirDownPath)
	assert.NoError(t, err)
	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
	assert.NoError(t, err)
	err = os.RemoveAll(mappedPath1)
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
	err = os.MkdirAll(subPath, 0777)
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
	err = os.Chmod(subPath, 0001)
	assert.NoError(t, err)
	err = scpDownload(localPath, remoteDownPath, false, false)
	assert.Error(t, err, "download a file with no system permissions must fail")

	err = os.Chmod(subPath, 0755)
	assert.NoError(t, err)
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
	testFileName := "test_file.dat"
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
	testFileName := "test_file.dat"
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
	testFileName := "test_file.dat"
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
	testFileName := "test_file.dat"
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
	u.QuotaSize = testFileSize - 1
	user, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	err = createTestFile(testFilePath, testFileSize)
	assert.NoError(t, err)
	remoteUpPath := fmt.Sprintf("%v@127.0.0.1:%v", user.Username, path.Join("/", testFileName))
	err = scpUpload(testFilePath, remoteUpPath, true, false)
	assert.NoError(t, err)
	err = scpUpload(testFilePath, remoteUpPath+".quota", true, false)
	assert.Error(t, err, "user is over quota scp upload must fail")

	err = os.Remove(testFilePath)
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
	err = os.MkdirAll(user.GetHomeDir(), 0777)
	assert.NoError(t, err)
	testDir := "testDir"
	linkPath := filepath.Join(homeBasePath, defaultUsername, testDir)
	err = os.Symlink(homeBasePath, linkPath)
	assert.NoError(t, err)
	testFileName := "test_file.dat"
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
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	testDirName := "testDir"
	testDirPath := filepath.Join(user.GetHomeDir(), testDirName)
	err = os.MkdirAll(testDirPath, 0777)
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
	testFileName := "test_file.dat"
	testFilePath := filepath.Join(homeBasePath, testFileName)
	testFileSize := int64(65535)
	testDirPath := filepath.Join(user.GetHomeDir(), testFileName)
	err = os.MkdirAll(testDirPath, 0777)
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
	usePubKey := true
	user, _, err := httpd.AddUser(getTestUser(usePubKey), http.StatusOK)
	assert.NoError(t, err)
	u := getTestUser(usePubKey)
	u.Username += "1"
	u.HomeDir += "1"
	user1, _, err := httpd.AddUser(u, http.StatusOK)
	assert.NoError(t, err)
	testFileName := "test_file.dat"
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
	testFileName := "test_file.dat"
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
	_, _, err = httpd.UpdateUser(user, http.StatusOK)
	assert.NoError(t, err)
	cmd := getScpDownloadCommand(localPath, remoteDownPath, false, false)
	go func() {
		err := cmd.Run()
		assert.Error(t, err, "SCP download must fail")
	}()
	waitForActiveTransfer()
	// wait some additional arbitrary time to wait for transfer activity to happen
	// it is need to reach all the code in CheckIdleConnections
	time.Sleep(100 * time.Millisecond)
	err = cmd.Process.Kill()
	assert.NoError(t, err)
	waitForNoActiveTransfer()
	cmd = getScpUploadCommand(testFilePath, remoteUpPath, false, false)
	go func() {
		err := cmd.Run()
		assert.Error(t, err, "SCP upload must fail")
	}()
	waitForActiveTransfer()
	// wait some additional arbitrary time to wait for transfer activity to happen
	// it is need to reach all the code in CheckIdleConnections
	time.Sleep(100 * time.Millisecond)
	err = cmd.Process.Kill()
	assert.NoError(t, err)
	waitForNoActiveTransfer()
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
		defer conn.Close()
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

func getCustomAuthSftpClient(user dataprovider.User, authMethods []ssh.AuthMethod) (*sftp.Client, error) {
	var sftpClient *sftp.Client
	config := &ssh.ClientConfig{
		User: user.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Auth: authMethods,
	}
	conn, err := ssh.Dial("tcp", sftpServerAddr, config)
	if err != nil {
		return sftpClient, err
	}
	sftpClient, err = sftp.NewClient(conn)
	return sftpClient, err
}

func createTestFile(path string, size int64) error {
	baseDir := filepath.Dir(path)
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		err = os.MkdirAll(baseDir, 0777)
		if err != nil {
			return err
		}
	}
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, content, 0666)
}

func appendToTestFile(path string, size int64) error {
	content := make([]byte, size)
	_, err := rand.Read(content)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0666)
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

func waitForNoActiveTransfer() {
	for len(sftpd.GetConnectionsStats()) > 0 {
		time.Sleep(100 * time.Millisecond)
	}
}

func waitForActiveTransfer() {
	stats := sftpd.GetConnectionsStats()
	for len(stats) < 1 {
		stats = sftpd.GetConnectionsStats()
	}
	activeTransferFound := false
	for !activeTransferFound {
		stats = sftpd.GetConnectionsStats()
		if len(stats) == 0 {
			break
		}
		for _, stat := range stats {
			if len(stat.Transfers) > 0 {
				activeTransferFound = true
			}
		}
	}
}

func waitQuotaScans() error {
	time.Sleep(100 * time.Millisecond)
	scans, _, err := httpd.GetQuotaScans(http.StatusOK)
	if err != nil {
		return err
	}
	for len(scans) > 0 {
		time.Sleep(100 * time.Millisecond)
		scans, _, err = httpd.GetQuotaScans(http.StatusOK)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkGitCommand() {
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
}

func initGitRepo(path string) ([]byte, error) {
	err := os.MkdirAll(path, 0777)
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

func getExtAuthScriptContent(user dataprovider.User, nonJSONResponse bool) []byte {
	extAuthContent := []byte("#!/bin/sh\n\n")
	u, _ := json.Marshal(user)
	extAuthContent = append(extAuthContent, []byte(fmt.Sprintf("if test \"$SFTPGO_AUTHD_USERNAME\" = \"%v\"; then\n", user.Username))...)
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
