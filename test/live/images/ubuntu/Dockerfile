FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ufw iptables socat procps iproute2 && rm -rf /var/lib/apt/lists/*
CMD ["sleep","infinity"]
