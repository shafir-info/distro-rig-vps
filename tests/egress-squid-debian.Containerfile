# Debian family (like ubuntu): squid-openssl is the OpenSSL/ssl-bump flavour dr-vps-setup installs on apt.
FROM docker.io/library/debian:trixie
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      squid-openssl dnsmasq openssl curl python3 iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
