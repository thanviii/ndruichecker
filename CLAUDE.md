# NDR Console Health Checker

## Goal
Build a simple, dockerized Python tool that checks, for a list of client NDR consoles (multiple vendors/platforms), whether each console is reachable and responding over HTTPS. It will be cloned from GitHub onto an Ubuntu automation server and run on a schedule (cron/systemd timer) via Docker.

This is a **reachability/health check only**. It must NOT log in, store credentials, or interact with the console beyond an unauthenticated HTTPS request.

## Requirements

### Targets / configuration
- Targets are defined in a YAML file (`config/targets.yaml`), mounted into the container at runtime. Never baked into the image and never committed to git.
- Provide `config/targets.example.yaml` (committed) with fake data. Add `config/targets.yaml` and `output/` to `.gitignore`.
- Per-target fields:
  - `client` (string, required)
  - `name` (string, required, e.g. "ExtraHop Prod")
  - `vendor` (string, optional, e.g. ExtraHop, Darktrace, Vectra, Corelight)
  - `url` (string, required, https URL; host:port allowed)
  - `verify_tls` (bool, default `true`; many consoles use self-signed certs so `false` must be supported per target)
  - `expected_status` (list of ints, default `[200, 301, 302, 303, 307, 308, 401, 403]`). Login pages commonly redirect or return 401/403, which still means the console is UP.
  - `timeout` (seconds, default 10)
  - `tags` (list, optional)
- Global defaults section in the YAML (`defaults:`) that targets can override: timeout, retries, verify_tls, expected_status, workers.
- Optional `proxy` setting (global or per-target) for environments that go out through a proxy.

### Checks per target (run in this order, record result of each)
1. **DNS resolution** of the hostname (skip if host is an IP).
2. **TCP connect** to host:port (default 443).
3. **TLS handshake** and read certificate expiry (days remaining). Do this even when `verify_tls: false` so expiry is still reported. Flag `WARN` if the cert expires in less than 30 days (configurable) and `FAIL` if already expired and verify is on.
4. **HTTPS GET** to the URL (follow redirects, max 5). Record the final status code and response time in ms. Status in `expected_status` = pass.

Final status per target:
- `UP` – all checks pass
- `WARN` – reachable but cert expiring soon, or response slower than a configurable threshold (default 5000 ms)
- `DOWN` – any hard failure (DNS, TCP, TLS, unexpected status, timeout)

Record the failure reason in plain text (e.g. "DNS resolution failed", "TCP timeout", "TLS: certificate verify failed", "HTTP 503").

### Behaviour
- Run targets concurrently (`ThreadPoolExecutor`, default 10 workers, configurable).
- Retries: default 2 retries with a short backoff before marking DOWN, to avoid false alarms from blips.
- Suppress `InsecureRequestWarning` when `verify_tls: false`.
- One target failing or raising an exception must never stop the run.

### Output
- Console summary table grouped by client (client, name, status, HTTP code, response ms, cert days left, reason). Plain text is fine; no heavy dependencies.
- Write a timestamped JSON report to `output/` (e.g. `output/report_YYYYMMDD_HHMMSS.json`) and also a CSV.
- Also write/overwrite `output/latest.json` for easy consumption.
- Exit codes: `0` = all UP, `1` = at least one WARN, `2` = at least one DOWN, `3` = config/usage error.
- Logging via the standard `logging` module, with `--verbose` flag for debug output.

### Optional notifications (keep simple, off by default)
- If env var `WEBHOOK_URL` is set, POST a short summary to it **only when there is at least one DOWN or WARN** (generic JSON payload that works with Teams/Slack-style incoming webhooks; keep the payload format easy to change).
- Secrets only via environment variables, never in the YAML or the repo.

### CLI
```
python -m ndr_checker --config config/targets.yaml --output-dir output [--workers 10] [--only-client NAME] [--tag TAG] [--verbose]
```

## Tech constraints
- Python 3.12, keep dependencies minimal: `requests`, `PyYAML`. Use stdlib `socket`, `ssl`, `concurrent.futures`, `argparse`, `json`, `csv`, `logging`.
- Pin versions in `requirements.txt`.
- Type hints and short docstrings. Keep the code small and readable; this is a utility, not a framework.

## Repo structure
```
.
├── CLAUDE.md
├── README.md
├── Dockerfile
├── .dockerignore
├── .gitignore
├── requirements.txt
├── config/
│   └── targets.example.yaml
├── ndr_checker/
│   ├── __init__.py
│   ├── __main__.py        # CLI entry point
│   ├── config.py          # load/validate YAML, apply defaults
│   ├── checks.py          # dns, tcp, tls, https checks
│   ├── runner.py          # concurrency + retries
│   ├── report.py          # console table, JSON, CSV
│   └── notify.py          # optional webhook
└── tests/
    └── test_checks.py     # pytest, mock network calls
```

## Docker
- Base image `python:3.12-slim`.
- Run as a **non-root user**.
- `ENTRYPOINT ["python", "-m", "ndr_checker"]` so extra args can be passed.
- Config and output are mounted as volumes, not copied into the image.
- Image must respect the container's CA bundle; allow an optional mounted custom CA bundle via `REQUESTS_CA_BUNDLE` for clients using internal CAs.
- Document example run in README:
```
docker build -t ndr-checker .
docker run --rm \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/output:/app/output \
  -e WEBHOOK_URL="${WEBHOOK_URL:-}" \
  ndr-checker --config /app/config/targets.yaml --output-dir /app/output
```
- Make sure the output directory is writable by the non-root container user (document the UID or handle it in the Dockerfile).

## README must include
- What it does and what it deliberately does not do (no logins, no credentials).
- Config file reference with a full example.
- Build and run instructions.
- Example **cron** entry for the Ubuntu server (e.g. weekdays at 07:30, logging to a file) and an optional systemd timer example.
- How to read exit codes in a scheduler/monitoring wrapper.
- Note that the automation server's source IP may need allow-listing on client firewalls.

## Testing / acceptance criteria
- `pytest` unit tests with network calls mocked: DNS failure, TCP timeout, TLS expiry parsing, expected status handling, retry logic, exit code mapping.
- Running with `targets.example.yaml` completes without crashing and produces console output, JSON and CSV.
- A deliberately bad target (unresolvable host) yields `DOWN` with a clear reason and exit code 2, while other targets still get checked.
- `docker build` succeeds and the container runs as non-root.
- No secrets or real client data anywhere in the repo.

## Git / GitHub
- Initialise git, make a clean first commit, and give me the exact commands to create the GitHub repo and push (private repo recommended since it describes client infrastructure patterns).
- Do not commit `config/targets.yaml`, `output/`, or any `.env` file.

## Out of scope (do not build)
- Authenticated checks, API calls to NDR vendors, or scraping consoles.
- A web UI, database, or long-running daemon. Scheduling is handled externally by cron/systemd on the host.

## Working style
Start by showing a brief plan, then build step by step. Ask me before adding any dependency beyond `requests` and `PyYAML`.
