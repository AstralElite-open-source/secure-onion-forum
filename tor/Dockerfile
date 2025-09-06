FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tor ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tor
COPY torrc /etc/tor/torrc

# Tor stores keys/hostname under /var/lib/tor; keep it in a volume
VOLUME ["/var/lib/tor"]

# Run tor in the foreground
CMD ["tor", "-f", "/etc/tor/torrc"]
