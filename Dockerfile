FROM alpine:3.8
LABEL maintainer="nekonekt@gmail.com"

ADD "./dist/gauth-server" "/bin/gauth-server"

EXPOSE 80
CMD ["/bin/gauth-server", "--config-path=/etc/gauth/config.json"]
