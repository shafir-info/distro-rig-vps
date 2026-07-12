# Security policy

distro-rig-vps runs a privileged installer (root), a hypervisor control plane, and host
network-confinement rules. Take vulnerabilities seriously and report them privately.

## Reporting a vulnerability

Please do NOT open a public issue for a security problem. Instead use GitHub's **private
vulnerability reporting** on this repository (Security tab → "Report a vulnerability"), or
email the author privately at <alexander@shafir.info> (see also <https://www.shafir.info>).

Include: the affected file/verb, the trust position of the attacker (agent in `drvpsctl`? host
user? guest root?), a reproduction, and the impact. Please redact any host-specific paths,
addresses, or credentials from logs before sending.

## Scope guidance

The trust model is documented in STATUS.md ("Trust model and load-bearing boundaries") and
CONCEPT.md. In particular: one rig is ONE agent trust domain; the watcher is trusted
infrastructure; the egress fence is test confinement, not a boundary against a root attacker on
the host. Reports that assume a stronger model than the documented one are still welcome, but
will be triaged against the documented boundaries.

## Supported versions

Pre-1.0: only the latest released version is supported; there are no security backports.
