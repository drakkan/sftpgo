FROM golang:1.12-alpine3.10 as builder

RUN apk add --no-cache git gcc g++ ca-certificates \
  && go get -u github.com/drakkan/sftpgo

FROM alpine:3.10

RUN  apk add --no-cache ca-certificates su-exec \
  && mkdir -p /data /etc/sftpgo

COPY --from=builder /go/bin/sftpgo /bin/
COPY docker-entrypoint.sh /bin/entrypoint.sh

VOLUME /data
EXPOSE 2022 8080

CMD ["/bin/entrypoint.sh"]
