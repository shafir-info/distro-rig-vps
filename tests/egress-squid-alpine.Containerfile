# Alpine family: `squid` (apk). bash needed for the test scripts.
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache squid dnsmasq openssl curl python3 iproute2 bash
