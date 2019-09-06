FROM debian:latest
LABEL maintainer="nicola.murino@gmail.com"
RUN apt-get update && apt-get install -y curl python3-requests python3-pygments

RUN curl https://raw.githubusercontent.com/drakkan/sftpgo/master/scripts/sftpgo_api_cli.py --output /usr/bin/sftpgo_api_cli.py

ENTRYPOINT ["python3", "/usr/bin/sftpgo_api_cli.py" ]
CMD []