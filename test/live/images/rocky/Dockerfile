FROM rockylinux:9
RUN dnf install -y systemd firewalld socat iproute procps-ng && dnf clean all && systemctl enable firewalld
CMD ["/usr/sbin/init"]
