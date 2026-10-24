# --- AmneziaWG (userspace) для ENGINE=awg: amneziawg-go + утилита awg ---
FROM golang:1.25-alpine AS awg
ARG AWG_GO_REF=v3.1.20260828
RUN apk add --no-cache git make gcc musl-dev linux-headers bash
RUN git clone --depth 1 --branch ${AWG_GO_REF} https://github.com/amnezia-vpn/amneziawg-go /src/awg-go \
 && cd /src/awg-go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/amneziawg-go .
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools /src/awg-tools \
 && make -C /src/awg-tools/src -j"$(nproc)" \
 && install -m 0755 /src/awg-tools/src/wg /out/awg

# --- usque (MASQUE-клиент WARP) для ENGINE=masque; HTTP/2-режим есть только после v1.5.0 ---
FROM golang:1.26-alpine AS usque
ARG USQUE_REF=6aa03fc97d12848dce34eedbd187fb1077b5d1ea
RUN apk add --no-cache git
RUN CGO_ENABLED=0 GOBIN=/out go install -trimpath -ldflags="-s -w" github.com/Diniboy1123/usque@${USQUE_REF}

# --- рабочий образ ---
FROM alpine:3.20
RUN apk add --no-cache python3 wireguard-tools-wg iproute2 curl ca-certificates tini openssl
COPY --from=awg /out/ /usr/local/bin/
COPY --from=usque /out/ /usr/local/bin/
COPY warp_pool.py /app/warp_pool.py
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/sbin/tini", "--", "python3", "/app/warp_pool.py"]
CMD ["run"]
