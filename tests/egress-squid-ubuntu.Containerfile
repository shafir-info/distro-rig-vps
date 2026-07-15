# Disposable Ubuntu squid-openssl test image for the egress live gate on the Debian/Ubuntu family
# (the deb family needs the OpenSSL flavour `squid-openssl`, which dr-vps-setup installs on
# apt -- the base `squid` is --with-gnutls and REJECTS ssl-bump). Built on demand; never touches the rig.
FROM docker.io/library/ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      squid-openssl dnsmasq openssl curl python3 iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
