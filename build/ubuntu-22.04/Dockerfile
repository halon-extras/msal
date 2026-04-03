FROM ubuntu:22.04
LABEL org.opencontainers.image.authors="support@halon.io"

ARG TARGETARCH
ARG TARGETOS

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN apt-get update

RUN apt-get update && apt-get install -y wget gnupg
RUN apt-get update && apt-get install -y apt-transport-https

RUN wget -qO - https://raw.githubusercontent.com/halon/changelog/master/pgp-keys/7F0A73B5.asc | apt-key add -
RUN echo "deb https://repo.halon.io/ jammy stable" >> /etc/apt/sources.list.d/halon.list
RUN echo "machine repo.halon.io login ${HALON_REPO_USER} password ${HALON_REPO_PASS}" >> /etc/apt/auth.conf
RUN apt-get update && apt-get install -y halon=6.0.0

RUN apt-get update && apt-get install -y build-essential cmake git curl file

RUN echo -n "UBU2204" > /OSRELEASE.txt

RUN mkdir /tmp/halon
RUN <<EOF
set -eu
cd /tmp/halon
case "$TARGETARCH" in
  amd64)
    SHA256=031f088e5d955bab8657ede27ad4e3bc5b7c1ba281f05f245bcc304f327c987a
    ;;
  arm64)
    SHA256=a290581cfe4fe28ddd737dde3095f3dbeb7f2e4065cab4eae44dfc53b760c2f7
    ;;
esac
curl -O -L https://go.dev/dl/go1.26.1.${TARGETOS}-${TARGETARCH}.tar.gz
echo "${SHA256} go1.26.1.${TARGETOS}-${TARGETARCH}.tar.gz" | sha256sum -c
tar -C /usr/local -xzf go1.26.1.${TARGETOS}-${TARGETARCH}.tar.gz
EOF
RUN /usr/local/go/bin/go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
RUN /usr/local/go/bin/go install github.com/google/go-licenses/v2@latest
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"

RUN rm -rf /tmp/halon

COPY build.sh /build.sh
CMD ["/build.sh"]
