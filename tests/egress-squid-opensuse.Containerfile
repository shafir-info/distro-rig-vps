# SUSE family: stock `squid` (zypper).
FROM registry.opensuse.org/opensuse/leap:15.6
RUN zypper -n --gpg-auto-import-keys refresh && zypper -n install squid dnsmasq openssl curl python3 iproute2 && zypper clean -a
