# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# A Linux development and test environment for Soglia.
#
# Soglia runs only on Linux, and only `soglia-core` and `soglia-proxy` build anywhere else, so on
# macOS or Windows the workspace is built, checked and exercised here: through `dev/linux/run.sh`, or
# opened in an editor through `.devcontainer/`, which uses this same image. For the privileged suite
# the container runs with its own cgroup namespace: its cgroup root is the subtree the container
# runtime delegated to it, which is where Soglia creates Execution cgroups.

FROM rust:1-trixie

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        clang \
        bpftool \
        iproute2 \
        libbpf-dev \
        libelf-dev \
        nftables \
        procps \
        runc \
        curl \
        jq \
        musl-tools \
        zlib1g-dev \
    && if [ "$(dpkg --print-architecture)" = amd64 ]; then \
        apt-get install --yes --no-install-recommends libc6-dev-i386; \
    fi \
    && rm -rf /var/lib/apt/lists/*

# Task, so `task <name>` works here as it does on a developer's machine. The version and the
# checksum of each architecture's archive are pinned: a new version is a reviewed change to this
# file, taken from the release's task_checksums.txt.
ARG TASK_VERSION=3.53.1
ARG TASK_SHA256_AMD64=a54a408f6861ff921f6e87774180db31bacd8c1e7c944ca696db9fea49a82fc7
ARG TASK_SHA256_ARM64=e3ad19101493a0112e1f22ae8ccc54bf03e533b1076a0ca1e6c782a09ad2e588
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
        amd64) sha256="$TASK_SHA256_AMD64" ;; \
        arm64) sha256="$TASK_SHA256_ARM64" ;; \
        *) echo "no pinned Task archive for $arch" >&2; exit 1 ;; \
    esac \
    && curl --fail --silent --show-error --location --output /tmp/task.tar.gz \
        "https://github.com/go-task/task/releases/download/v${TASK_VERSION}/task_linux_${arch}.tar.gz" \
    && echo "${sha256}  /tmp/task.tar.gz" | sha256sum --check --strict - \
    && tar --extract --gzip --file /tmp/task.tar.gz --directory /usr/local/bin task \
    && rm /tmp/task.tar.gz \
    && task --version

RUN rustup component add clippy rustfmt rust-src llvm-tools-preview \
    && rustup target add "$(uname -m)-unknown-linux-musl" \
    && cargo install --locked cargo-deny cargo-llvm-cov

# Tells `dev/linux/acceptance.sh` it is already inside the development environment.
ENV SOGLIA_DEV_CONTAINER=1

WORKDIR /work
