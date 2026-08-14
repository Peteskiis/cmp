# Hosted Testing Service Privacy Notice

This notice applies to the experimental relay at `cmp.clusterbase.dev`. It does
not apply to independently operated CMP servers. The hosted endpoint is a
development service, not a generally available communications product.

## Data processed

The relay processes usernames, source IP and connection metadata, public
identity/prekey material, sender and recipient identifiers, timestamps,
ciphertext sizes, encrypted message and receipt payloads, and delivery state.
Hosting and reverse-proxy infrastructure may also produce operational logs.

Message plaintext, identity private keys, ratchet keys, and local message
history are intended to remain on client devices. End-to-end encryption does
not conceal account relationships, timing, traffic volume, or ciphertext sizes
from the relay.

## Purpose and retention

Data is processed to authenticate accounts, establish encrypted sessions,
route ciphertext, retry offline delivery, prevent abuse, and debug service
failures.

- queued messages are garbage-collected after approximately 30 days;
- public prekey material uses bounded protocol lifetimes;
- receipts and delivery-confirmation records remain until their correlated
  handshake completes or the testing service is reset;
- account identity records may remain for the life of the testing service;
- operational-log retention depends on the hosting environment and has no
  published guarantee during this experimental period.

The service has no self-service account export or deletion flow. Avoid using it
if those controls are required. The operator may reset or delete any testing
data without notice.

## Sharing and security

Data is processed by the infrastructure required to host the relay. It is not
intended for sale or advertising. No security guarantee can eliminate the risk
of service compromise, endpoint compromise, implementation defects, or legal
disclosure requirements.

For a sensitive privacy concern, use the repository's private GitHub security
advisory channel described in [SECURITY.md](SECURITY.md). Do not include private
keys or message plaintext. Non-sensitive questions may use a public discussion
or issue after the repository becomes public.
