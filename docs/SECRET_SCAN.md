# Git-history secret scan

Before public visibility, the complete repository history was scanned with
Gitleaks v8.30.1 using its default rules and full redaction.

```sh
gitleaks git --redact --no-banner --no-color --log-opts="--all" \
  --report-format json --report-path /tmp/cmp-gitleaks.json .
```

Scan record:

- date: 2026-08-14 UTC;
- base revision: `4f64ba7b7e375f349976834b40f4221615fb2f6f`;
- refs: all refs reachable through `git log --all`;
- findings: 0;
- report contents: not committed.

The current source tree was separately scanned from a temporary snapshot built
with `git ls-files --cached --others --exclude-standard`, excluding ignored
build output and local databases. A clean automated scan reduces risk but does
not prove that history is free of every sensitive value. Repository visibility
must not change until the latest scan and a manual review of
deployment/configuration files are both clean.
