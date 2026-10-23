FROM debian:bookworm@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931

ARG NODE_VERSION=24.21.0
ARG NODE_LINUX_X64_SHA256=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN sed -i 's/Components: main$/Components: main contrib/' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
    adb autoconf automake bc bison build-essential ca-certificates cabal-install \
    curl diffutils file flex fontconfig fonts-dejavu-core git git-lfs gnupg \
    gperf libffi-dev libgmp-dev libncurses-dev libnuma-dev libtool libx11-6 \
    libxcb1 libxcomposite1 libxcursor1 libxi6 libxrandr2 libxrender1 \
    libxtst6 libpulse0 libnss3 libglu1-mesa libasound2 libtinfo5 \
    libdrm2 libgbm1 libxkbcommon0 shellcheck \
    openssh-client openssl patch pkg-config procps python3 repo rsync unzip xz-utils \
    yarnpkg zip zlib1g-dev && rm -rf /var/lib/apt/lists/*

# adevtool requires Node.js 24 LTS. Keep the upstream archive immutable and
# checksum-verified; Debian's yarnpkg uses /usr/bin/env and therefore resolves
# this pinned runtime through PATH rather than Bookworm's older node binary.
RUN archive="node-v${NODE_VERSION}-linux-x64.tar.xz" \
    && curl -fsSLo "/tmp/${archive}" "https://nodejs.org/dist/v${NODE_VERSION}/${archive}" \
    && echo "${NODE_LINUX_X64_SHA256}  /tmp/${archive}" | sha256sum -c - \
    && mkdir -p /opt/node \
    && tar -xJf "/tmp/${archive}" --strip-components=1 -C /opt/node \
    && ln -s /opt/node/bin/node /usr/local/bin/node \
    && ln -s /opt/node/bin/npm /usr/local/bin/npm \
    && ln -s /opt/node/bin/npx /usr/local/bin/npx \
    && rm -f "/tmp/${archive}"

ENV PATH=/opt/node/bin:$PATH

RUN test "$(node --version)" = "v${NODE_VERSION}" \
    && yarnpkg --version

RUN groupadd --gid 1000 builder && useradd --uid 1000 --gid 1000 --create-home builder
USER builder
WORKDIR /sources
