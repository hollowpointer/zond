FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    net-tools \
    iputils-ping \
    tcpdump \
    netcat-openbsd \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PATH="/app:${PATH}"

CMD ["tail", "-f", "/dev/null"]
