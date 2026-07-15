# RHEL family (like fedora): stock `squid` is OpenSSL/ssl-bump. curl-minimal (preinstalled) provides curl.
FROM docker.io/library/rockylinux:9
RUN dnf -y install --setopt=install_weak_deps=False squid dnsmasq openssl python3 iproute && dnf clean all
