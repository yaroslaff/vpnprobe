# Repository instructions

## Scope and architecture

- Build `vpnprobe`, an unprivileged Python 3.13 library for checking SS, VLESS,
  Hysteria2, MTProto proxy, and VPN subscription URLs, plus a `ping` CLI for
  direct VPN and MTProto proxy URLs and a `subscription`/`sub` CLI for
  downloading, decoding, and printing subscription entries without probing them.
- Keep `vpnprobe` independent of vpnshare persistence and product logic. Do not add SQLite, SQLAlchemy, Alembic, Telegram Bot API, user, distribution, or scheduling dependencies.
- Expose one typed asyncio-native Python API and make the CLI a thin adapter over that API.
- Keep the `ping` contract intentionally minimal: its required result is only whether the probe succeeded, represented by a conventional integer status code. Structured latency, speed, DC, or diagnostic results are not required. The library may print or inherit useful human-readable output from probe tools such as xray-knife so an interactive user can see optional details.
- Do not read vpnshare configuration or databases. Accept inputs and options explicitly and write only disposable runtime data to temporary directories.

## Platform and quality

- Target Debian 13 and Python 3.13 exclusively.
- Use modern typed Python, mypy strict mode, Ruff, pytest with pytest-asyncio, and at least 90% test coverage.
- Pin dependencies exactly and package with Hatchling.
- Ordinary tests must not require external network access, real VPN keys, TDLib, xray-knife, or sing-box.
- Keep code, identifiers, CLI output, logs, diagnostics, and developer documentation in English.
- Do not add server-side CI; checks run locally.

## Development workflow

- After completing and verifying any file changes, ask the user whether to create a Git commit unless the user already explicitly requested a commit.
- Commit directly to `master`; do not create feature branches.
- Every commit that raises the package version must get a Git tag named exactly after the new version, without a `v` prefix (for example `0.3.2`). Push the tag together with the commit.

## Security and runtime

- Never require root, privileged containers, elevated Linux capabilities, or access to the vpnshare database.
- Treat VPN URLs, proxy credentials, and subscription URLs as secrets. Do not persist them or expose them in unexpected diagnostics.
- This is a personal, single-user project: passing VPN URLs and MTProto proxy URLs in child-process command-line arguments is acceptable because all processes and secrets are accessible only to the owner. Do not treat command-line visibility to the same OS user as a vulnerability.
- Clean up all temporary files, TDLib state, tunnel processes, and process groups after success, failure, timeout, or interruption.
