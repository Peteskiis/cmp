# Hosted experimental service

The client defaults to `wss://cmp.clusterbase.dev/ws`. This endpoint exists for
development and interoperability testing. It is not a production messaging
service and has no uptime, durability, support, retention, privacy, or abuse
response SLA.

The hosted relay can observe account names, source IP addresses, public key
material, sender/recipient relationships, timing, frequency, ciphertext sizes,
and delivery state. It stores account data, queued ciphertext, and delivery
metadata in order to operate the protocol. Message plaintext and client private
keys are not intentionally sent to the relay.

See [../PRIVACY.md](../PRIVACY.md) for data practices and
[../ACCEPTABLE_USE.md](../ACCEPTABLE_USE.md) for use restrictions.

Do not use the hosted endpoint for sensitive, regulated, safety-critical, or
illegal communications. Service data may be deleted during testing, upgrades,
abuse response, or shutdown. A formal privacy notice and abuse process must be
published before the endpoint is represented as a generally available service.

Run a self-hosted relay and pass `--server <url>` if these terms are unsuitable.
Security vulnerabilities belong in the private channel described by
`SECURITY.md`; do not send private message content in a public report.
