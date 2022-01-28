FROM ubuntu:18.04
LABEL org.opencontainers.image.authors="support@halon.io"

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN apt-get update

RUN apt-get install -y wget gnupg
RUN apt-get install -y apt-transport-https

RUN wget -qO - https://raw.githubusercontent.com/halon/changelog/master/pgp-keys/7F0A73B5.asc | apt-key add -
RUN echo "deb https://repo.halon.io/ bionic stable" >> /etc/apt/sources.list.d/halon.list
RUN echo "machine repo.halon.io login ${HALON_REPO_USER} password ${HALON_REPO_PASS}" >> /etc/apt/auth.conf
RUN apt-get update && apt-get install -y halon=5.8.0

RUN apt-get install -y build-essential cmake git curl

RUN echo -n "UBU1804" > /OSRELEASE.txt

RUN mkdir /tmp/halon
RUN cd /tmp/halon \
    && curl -O -L https://go.dev/dl/go1.17.6.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.17.6.linux-amd64.tar.gz

RUN mkdir /licenses
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/AzureAD/microsoft-authentication-library-for-go/dev/LICENSE \
    && cp LICENSE /licenses/LICENSE.microsoft-authentication-library-for-go
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/google/uuid/master/LICENSE \
    && cp LICENSE /licenses/LICENSE.google-uuid
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/pkg/browser/master/LICENSE \
    && cp LICENSE /licenses/LICENSE.pkg-browser
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/golang-jwt/jwt/main/LICENSE \
    && cp LICENSE /licenses/LICENSE.golang-jwt
RUN cd /tmp/halon \
    && curl -O -L https://raw.githubusercontent.com/kylelemons/godebug/master/LICENSE \
    && cp LICENSE /licenses/LICENSE.godebug

RUN rm -rf /tmp/halon

COPY build.sh /build.sh
CMD ["/build.sh"]
