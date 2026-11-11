# Serrier

Security tooling for AI-assisted development, running locally: a repo scanner and a
**Pre-Send Guardian** that stops secrets before they are sent to an AI provider.

Serrier never claims a system is "secure" — it reports what it found, with evidence, and
states its coverage limits.

## Install

```bash
pip install serrier
```

Requires Python 3.12+ (Linux/macOS; Windows is untested). `pipx install serrier` or
`uv tool install serrier` keep it isolated from your other packages.

## Use

**Scan a repository** — local, no server, nothing leaves your machine:

```bash
serrier scan /path/to/repo
```

A built-in secret scanner always runs. If `gitleaks`, `osv-scanner` or `semgrep` are installed
they are used too; missing coverage is reported, not hidden.

**Pre-Send Guardian** — a loopback proxy that inspects outbound AI-API requests and blocks
secrets / redacts PII before they reach the provider:

```bash
serrier up                   # start the Guardian on 127.0.0.1
source ~/.serrier/env.sh     # point ANTHROPIC_BASE_URL / OPENAI_BASE_URL / … at it
claude                       # …or any AI tool that respects *_BASE_URL
serrier status
serrier down
```

Or wrap a single command: `serrier run -- <command>`.

State lives in `~/.serrier/` (override with `SERRIER_HOME`).

## Honest limits

- The Guardian only protects tools that respect `*_BASE_URL` and actually route through it.
  There is no transparent MITM; MCP, arbitrary HTTP and response content are not covered.
- Detection is local and deterministic, and conservative by design — it will miss things.
- No control has been independently verified yet.

## More

This package is the backend and CLI. The dashboard, the browser extension, the threat model
and the security documentation live in the repository:
<https://github.com/carlkjoels/serrier>

Licensed under the Apache License 2.0.
