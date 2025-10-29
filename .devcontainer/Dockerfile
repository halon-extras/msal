FROM --platform=linux/amd64 ubuntu:24.04
LABEL org.opencontainers.image.authors="support@halon.io"

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN apt-get update

RUN apt-get install -y wget gnupg
RUN apt-get install -y apt-transport-https

RUN wget -qO - https://raw.githubusercontent.com/halon/changelog/master/pgp-keys/7F0A73B5.asc | apt-key add -
RUN echo "deb https://repo.halon.io/ noble stable" >> /etc/apt/sources.list.d/halon.list
RUN echo "machine repo.halon.io login ${HALON_REPO_USER} password ${HALON_REPO_PASS}" >> /etc/apt/auth.conf
RUN apt-get update && apt-get install -y halon=6.3.0

RUN /usr/bin/install -d /var/run/halon
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH

RUN apt-get install -y build-essential cmake git curl

RUN echo -n "UBU2404" > /OSRELEASE.txt

RUN mkdir /tmp/halon
RUN cd /tmp/halon \
    && curl -O -L https://go.dev/dl/go1.23.4.linux-amd64.tar.gz \
    && echo "6924efde5de86fe277676e929dc9917d466efa02fb934197bc2eba35d5680971 go1.23.4.linux-amd64.tar.gz" | sha256sum -c \
    && tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
RUN /usr/local/go/bin/go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"

RUN mkdir /licenses
RUN cp /usr/local/go/LICENSE /licenses/LICENSE.go
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

RUN apt-get install -y supervisor
COPY .devcontainer/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
CMD ["/usr/bin/supervisord"]