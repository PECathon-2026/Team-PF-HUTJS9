# PrivacyLens dev image (owner: LNX). AD-03: every C++/Python build and test runs here.
#
# Reproducibility:
#   - the base image is pinned by digest;
#   - apt packages come from a fixed snapshot.ubuntu.com timestamp, so every
#     package version is frozen (change UBUNTU_SNAPSHOT to move them all at once);
#   - every downloaded tarball/binary is verified by SHA-256.
# The image tag is the hash of this file (see the Makefile), so any edit here
# produces a new tag. Prefer Ubuntu packages / official prebuilt binaries over
# source builds: the LNX laptop has 8 GB RAM.
#
# Deviation notes:
#   - Vectorscan: Ubuntu 24.04 ships Hyperscan 5.4.2 (libhyperscan-dev) on amd64.
#     Vectorscan is its API-compatible fork; we use the packaged library.
#   - pocketfft/FFTW: FFTW (libfftw3-dev).
#   - json-schema-validator is built with Boost.Regex (JSON_SCHEMA_BOOST_REGEX):
#     std::regex recurses per character and overflows the stack on long strings
#     (Phase 0 review); consumers link Boost::regex (contracts/lib/CMakeLists.txt).
#   - ca-certificates is installed from the live archive before the switch to the
#     snapshot (snapshot.ubuntu.com is HTTPS-only); everything after is frozen.
#   - LightGBM: the official manylinux shared library from the PyPI wheel, plus
#     the C API headers from the matching source release.

FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ARG DEBIAN_FRONTEND=noninteractive
ARG UBUNTU_SNAPSHOT=20261029T000000Z
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# ca-certificates first (snapshot.ubuntu.com is HTTPS-only), then switch every
# apt source to the frozen snapshot.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && sed -i -E "s#http://(archive|security)\.ubuntu\.com/ubuntu/?#https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/#" /etc/apt/sources.list.d/ubuntu.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc-13 g++-13 make pkg-config \
      clang-18 clang-tidy-18 clang-format-18 libclang-rt-18-dev llvm-18 lld-18 \
      cmake ninja-build ccache \
      git curl xz-utils unzip file jq strace gdb \
      libgtest-dev libgmock-dev libbenchmark-dev librapidcheck-dev \
      libsodium-dev libhyperscan-dev libeigen3-dev libboost-regex-dev \
      libopencv-core-dev libopencv-imgproc-dev libopencv-imgcodecs-dev \
      libfftw3-dev nlohmann-json3-dev libyaml-cpp-dev libspdlog-dev libfmt-dev libcli11-dev \
      libsqlite3-dev sqlite3 \
      libtesseract-dev libleptonica-dev tesseract-ocr tesseract-ocr-eng \
      libbpf-dev libelf-dev zlib1g-dev \
      python3.12 python3.12-dev python3.12-venv \
      lcov libgomp1 \
 && rm -rf /var/lib/apt/lists/* \
 && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 100 \
 && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 100 \
 && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 \
 && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100 \
 && update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-18 100 \
 && update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-18 100 \
 && update-alternatives --install /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-18 100 \
 && update-alternatives --install /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-18 100 \
 && update-alternatives --install /usr/bin/llvm-symbolizer llvm-symbolizer /usr/bin/llvm-symbolizer-18 100

# ---- pinned downloads (URL, SHA-256) -----------------------------------------
ARG UV_VERSION=0.12.24
ARG UV_SHA256=b4dfaef47d491a7296981f8374a4595f55dbf84e8937c8ecd2983574d8bb3da6
ARG NODE_VERSION=22.23.3
ARG NODE_SHA256=df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de
ARG PNPM_VERSION=10.34.6
ARG PNPM_SHA256=44d7db90fcbb2315b581f85989a913466765421fc656c28e80fac1b7ab5be456
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG BPFTOOL_VERSION=7.7.0
ARG BPFTOOL_SHA256=09150596f09356b0ff632dd7f9856e0ea86bf96b269e9bc94278d9a9432a268c
ARG ORT_VERSION=1.30.0
ARG ORT_SHA256=a5ed5a3cac51fbb2e90da632ae43d19212faaa20e76484e62bcb7c23ddb3b3fd
ARG LIGHTGBM_VERSION=4.7.0
ARG LIGHTGBM_WHEEL_URL=https://files.pythonhosted.org/packages/15/eb/837ea3b40cc36e22eeebb9785c01e42b2c255d033eea1d2d9ee8e2540e55/lightgbm-4.7.0-py3-none-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl
ARG LIGHTGBM_WHEEL_SHA256=d23e922acd891e77212e4d0fbcee9ba973c96dee479491341d05ba595357ebb7
ARG LIGHTGBM_SRC_SHA256=2463b653b456cb3c9816dd014105d05917e38432f360f9e9739b5446fac9021d
ARG SQLITE_VEC_VERSION=0.1.9
ARG SQLITE_VEC_SHA256=3acd67cb4aff080c7050926fd3cf8227905fe5b7ee3829d8ee5024ab1283cf61
ARG JSV_VERSION=2.4.0
ARG JSV_SHA256=24cbb114609cc9b43d4018b8d03e082ff5d2f26f5dce8bd36538097267b63af9
ARG COMPOSE_VERSION=5.6.0
ARG COMPOSE_SHA256=40343e21ca777173e69cff5dbafeb37c6f81f3b0d57d9e597f036e95eb63e76a

RUN set -eux; mkdir -p /tmp/dl && cd /tmp/dl; \
    fetch() { curl -fsSL --retry 5 --retry-all-errors --connect-timeout 20 --max-time 900 -o "$2" "$1"; echo "$3  $2" | sha256sum -c -; }; \
    \
    fetch "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz" uv.tgz "${UV_SHA256}"; \
    tar xzf uv.tgz --strip-components=1 -C /usr/local/bin uv-x86_64-unknown-linux-gnu/uv uv-x86_64-unknown-linux-gnu/uvx; \
    \
    fetch "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" node.txz "${NODE_SHA256}"; \
    mkdir -p /opt/node && tar xJf node.txz --strip-components=1 -C /opt/node; \
    for b in node npm npx corepack; do ln -s /opt/node/bin/$b /usr/local/bin/$b; done; \
    fetch "https://registry.npmjs.org/pnpm/-/pnpm-${PNPM_VERSION}.tgz" pnpm.tgz "${PNPM_SHA256}"; \
    npm install -g --no-fund --no-audit ./pnpm.tgz; ln -s /opt/node/bin/pnpm /usr/local/bin/pnpm; \
    \
    fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks.tgz "${GITLEAKS_SHA256}"; \
    tar xzf gitleaks.tgz -C /usr/local/bin gitleaks; \
    \
    fetch "https://github.com/libbpf/bpftool/releases/download/v${BPFTOOL_VERSION}/bpftool-v${BPFTOOL_VERSION}-amd64.tar.gz" bpftool.tgz "${BPFTOOL_SHA256}"; \
    tar xzf bpftool.tgz -C /usr/local/bin bpftool; chmod 0755 /usr/local/bin/bpftool; \
    \
    fetch "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-x86_64" docker-compose "${COMPOSE_SHA256}"; \
    install -m 0755 docker-compose /usr/local/bin/docker-compose; \
    \
    fetch "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-x64-${ORT_VERSION}.tgz" ort.tgz "${ORT_SHA256}"; \
    mkdir -p /opt/onnxruntime && tar xzf ort.tgz --strip-components=1 -C /opt/onnxruntime; \
    \
    fetch "${LIGHTGBM_WHEEL_URL}" lightgbm.whl "${LIGHTGBM_WHEEL_SHA256}"; \
    fetch "https://github.com/microsoft/LightGBM/archive/refs/tags/v${LIGHTGBM_VERSION}.tar.gz" lightgbm-src.tgz "${LIGHTGBM_SRC_SHA256}"; \
    mkdir -p /opt/lightgbm/lib /opt/lightgbm/include; \
    unzip -q -j lightgbm.whl lightgbm/lib/lib_lightgbm.so -d /opt/lightgbm/lib; \
    tar xzf lightgbm-src.tgz --strip-components=2 -C /opt/lightgbm/include "LightGBM-${LIGHTGBM_VERSION}/include/LightGBM"; \
    \
    fetch "https://github.com/asg017/sqlite-vec/releases/download/v${SQLITE_VEC_VERSION}/sqlite-vec-${SQLITE_VEC_VERSION}-amalgamation.tar.gz" sqlite-vec.tgz "${SQLITE_VEC_SHA256}"; \
    mkdir -p /opt/sqlite-vec/src /opt/sqlite-vec/lib /opt/sqlite-vec/include; tar xzf sqlite-vec.tgz -C /opt/sqlite-vec/src; \
    cp /opt/sqlite-vec/src/sqlite-vec.h /opt/sqlite-vec/include/; \
    gcc -O2 -fPIC -shared /opt/sqlite-vec/src/sqlite-vec.c -o /opt/sqlite-vec/lib/vec0.so -lm; \
    gcc -O2 -fPIC -DSQLITE_CORE -c /opt/sqlite-vec/src/sqlite-vec.c -o /tmp/dl/sqlite-vec.o && ar rcs /opt/sqlite-vec/lib/libsqlite_vec.a /tmp/dl/sqlite-vec.o; \
    \
    fetch "https://github.com/pboettch/json-schema-validator/archive/refs/tags/${JSV_VERSION}.tar.gz" jsv.tgz "${JSV_SHA256}"; \
    tar xzf jsv.tgz; \
    cmake -S "json-schema-validator-${JSV_VERSION}" -B jsv-build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DJSON_VALIDATOR_INSTALL=ON -DJSON_VALIDATOR_BUILD_TESTS=OFF \
      -DJSON_VALIDATOR_BUILD_EXAMPLES=OFF -DJSON_VALIDATOR_SHARED_LIBS=OFF -DCMAKE_CXX_FLAGS=-DJSON_SCHEMA_BOOST_REGEX \
      -DFETCHCONTENT_TRY_FIND_PACKAGE_MODE=ALWAYS -DFETCHCONTENT_FULLY_DISCONNECTED=ON; \
    cmake --build jsv-build -j4 && cmake --install jsv-build --prefix /usr/local; \
    \
    printf '/opt/onnxruntime/lib\n/opt/lightgbm/lib\n/opt/sqlite-vec/lib\n' > /etc/ld.so.conf.d/privacylens.conf && ldconfig; \
    cd / && rm -rf /tmp/dl /root/.npm

# ---- environment -------------------------------------------------------------
# Containers run as the host uid (no passwd entry), so HOME and caches live in
# /cache, which `make` mounts as a named volume (world-writable, sticky).
RUN mkdir -p /cache/home /cache/ccache /cache/uv /cache/venv /cache/pnpm && chmod -R 1777 /cache \
 && git config --system --add safe.directory '*'

ENV PL_IN_DEV=1 \
    HOME=/cache/home \
    CCACHE_DIR=/cache/ccache \
    UV_CACHE_DIR=/cache/uv \
    UV_PYTHON=/usr/bin/python3.12 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    PNPM_HOME=/cache/pnpm \
    CMAKE_GENERATOR=Ninja \
    CMAKE_BUILD_PARALLEL_LEVEL=4 \
    CMAKE_PREFIX_PATH=/opt/onnxruntime:/opt/lightgbm:/opt/sqlite-vec \
    CC=gcc CXX=g++

WORKDIR /work
CMD ["bash"]
