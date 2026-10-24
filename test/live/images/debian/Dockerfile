FROM debian:12
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables iptables socat procps iproute2 curl ca-certificates && rm -rf /var/lib/apt/lists/*
CMD ["sleep","infinity"]
