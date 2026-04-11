FROM ubuntu:22.04 AS builder
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
        rm /var/lib/dpkg/info/libc-bin.* && \
        apt-get clean && \
        apt-get update && \
        apt install libc-bin && \
        apt-get install -y build-essential cmake clang gperf wget git \
        ninja-build pkg-config autoconf automake libtool \
        libjemalloc-dev lsb-release software-properties-common gnupg

RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 21 all && \
    rm -rf /var/lib/apt/lists/*

ENV CC=/usr/bin/clang-21
ENV CXX=/usr/bin/clang++-21
ENV CCACHE_DISABLE=1

WORKDIR /
RUN mkdir tos
WORKDIR /tos

COPY ./ ./

RUN mkdir build && \
        cd build && \
        cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DPORTABLE=1 -DTOS_ARCH= -DTOS_USE_JEMALLOC=ON .. && \
        ninja storage-daemon storage-daemon-cli toslibjson fift func validator-engine validator-engine-console \
    generate-random-id dht-server lite-client tolk rldp-http-proxy dht-server proxy-liteserver create-state \
    blockchain-explorer emulator toslibjson http-proxy adnl-proxy dht-ping-servers dht-resolve

FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y wget curl libatomic1 openssl libsodium-dev libmicrohttpd-dev liblz4-dev libjemalloc-dev htop \
    net-tools netcat iptraf-ng jq tcpdump pv plzip && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/tos-work/db /var/tos-work/scripts /usr/share/tos/smartcont/auto /usr/lib/fift/

COPY --from=builder /tos/build/storage/storage-daemon/storage-daemon /usr/local/bin/
COPY --from=builder /tos/build/storage/storage-daemon/storage-daemon-cli /usr/local/bin/
COPY --from=builder /tos/build/lite-client/lite-client /usr/local/bin/
COPY --from=builder /tos/build/validator-engine/validator-engine /usr/local/bin/
COPY --from=builder /tos/build/validator-engine-console/validator-engine-console /usr/local/bin/
COPY --from=builder /tos/build/utils/generate-random-id /usr/local/bin/
COPY --from=builder /tos/build/blockchain-explorer/blockchain-explorer /usr/local/bin/
COPY --from=builder /tos/build/crypto/create-state /usr/local/bin/
COPY --from=builder /tos/build/utils/proxy-liteserver /usr/local/bin/
COPY --from=builder /tos/build/dht-server/dht-server /usr/local/bin/
COPY --from=builder /tos/build/dht/dht-ping-servers /usr/local/bin/
COPY --from=builder /tos/build/dht/dht-resolve /usr/local/bin/
COPY --from=builder /tos/build/rldp-http-proxy/rldp-http-proxy /usr/local/bin/
COPY --from=builder /tos/build/http/http-proxy  /usr/local/bin/
COPY --from=builder /tos/build/adnl/adnl-proxy  /usr/local/bin/
COPY --from=builder /tos/build/toslib/libtoslibjson.so /usr/local/bin/
COPY --from=builder /tos/build/emulator/libemulator.so /usr/local/bin/
COPY --from=builder /tos/build/tolk/tolk /usr/local/bin/
COPY --from=builder /tos/build/crypto/fift /usr/local/bin/
COPY --from=builder /tos/build/crypto/func /usr/local/bin/
COPY --from=builder /tos/crypto/smartcont/* /usr/share/tos/smartcont/
COPY --from=builder /tos/crypto/smartcont/auto/* /usr/share/tos/smartcont/auto/
COPY --from=builder /tos/crypto/fift/lib/* /usr/lib/fift/

WORKDIR /var/tos-work/db
COPY ./docker/init.sh ./docker/control.template /var/tos-work/scripts/
RUN chmod +x /var/tos-work/scripts/init.sh

ENTRYPOINT ["/var/tos-work/scripts/init.sh"]
