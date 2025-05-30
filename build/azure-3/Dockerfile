FROM --platform=linux/amd64 mcr.microsoft.com/azurelinux/base/core:3.0
LABEL org.opencontainers.image.authors="support@halon.io"

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN tdnf install -y ca-certificates azurelinux-repos-extended

RUN echo "[halon]" >> /etc/yum.repos.d/Halon.repo
RUN echo "name=Halon repository" >> /etc/yum.repos.d/Halon.repo
RUN echo "baseurl=https://${HALON_REPO_USER}:${HALON_REPO_PASS}@repo.halon.io/dists/azure3/amd64/stable" >> /etc/yum.repos.d/Halon.repo
RUN echo "gpgcheck=1" >> /etc/yum.repos.d/Halon.repo
RUN echo "gpgkey=https://raw.githubusercontent.com/halon/changelog/master/pgp-keys/7F0A73B5.asc" >> /etc/yum.repos.d/Halon.repo
RUN echo "enabled=1" >> /etc/yum.repos.d/Halon.repo
RUN tdnf install -y halon-6.7.0

RUN tdnf install -y cmake3 make gcc-c++ rpm-build clang build-essential

RUN echo -n "AZURE3" > /OSRELEASE.txt

RUN mkdir /tmp/halon
RUN cd /tmp/halon \
    && curl -O -L https://go.dev/dl/go1.23.4.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz

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

COPY build.sh /build.sh
CMD ["/build.sh"]
