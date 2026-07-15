# Disposable squid 7.x test image for the egress live release-gate (PLAN Task 1.10). Built on demand
# by tests/egress-squid-run.sh; never touches the shared rig.
FROM quay.io/fedora/fedora:44
RUN dnf -y install --setopt=install_weak_deps=False squid dnsmasq openssl curl python3 iproute && dnf clean all
