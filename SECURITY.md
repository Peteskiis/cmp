# Security Policy

## Experimental status

CMP is experimental, unaudited software. No release is currently supported for
production use. Until a tagged alpha exists, security fixes are made only on
`main` and may include breaking protocol or storage changes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
[security advisory form](https://github.com/Peteskiis/cmp/security/advisories/new)
and include:

- the affected revision and component;
- a minimal reproduction or attack path;
- the expected security property and observed behavior;
- any evidence needed to assess impact, with secrets and personal data removed.

You should receive an acknowledgement within seven days. There is no bug bounty
or guaranteed remediation timeline. Please allow time for a fix and coordinated
disclosure before publishing details.

## Scope

Reports about cryptographic state corruption, authentication bypass, plaintext
exposure, key compromise, metadata exposure beyond the documented threat model,
queue authorization, and unsafe release artifacts are in scope. Availability
or privacy expectations that are explicitly excluded in
[THREAT_MODEL.md](THREAT_MODEL.md) are still welcome as hardening suggestions,
but may not be treated as vulnerabilities.

Never include live credentials, private keys, message plaintext, or another
person's account data in a report.
