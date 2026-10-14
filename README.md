# NDR Console Health Checker

A simple, dockerized Python tool that checks whether a list of NDR (Network Detection & Response) consoles are reachable and responding over HTTPS.

## What It Does

- **Checks console reachability** over HTTPS (no authentication required)
- **Performs health checks** in this order:
  1. DNS resolution of the hostname
  2. TCP connectivity to the host:port
  3. TLS handshake and certificate expiry analysis
  4. HTTPS GET request and response status
- **Reports status** for each console: `UP`, `WARN` (cert expiring soon or slow response), or `DOWN` (any failure)
- **Runs concurrently** for fast execution across many targets
- **Retries failed checks** to avoid false alarms from transient blips
- **Generates reports** in JSON, CSV, and console table formats
- **Sends optional webhooks** to Teams/Slack when issues are detected

## What It Does NOT Do

- **No authentication**: This is a reachability check only; it does not log in or interact with console APIs
- **No credentials stored**: Secrets are never persisted in the config or container image
- **No long-running daemon**: It's designed to run on a schedule (cron/systemd timer)
- **No database**: Results are stored as files, not in a persistent database

## Quick Start

### 1. Clone and Prepare

```bash
git clone <your-repo> ndr-checker
cd ndr-checker
```

### 2. Create a Config File

Copy the example config and edit with your targets:

```bash
cp config/targets.example.yaml config/targets.yaml
# Edit config/targets.yaml with your console URLs and settings
```

### 3. Build the Docker Image

```bash
docker build -t ndr-checker .
```

### 4. Run the Check

```bash
docker run --rm \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/output:/app/output \
  ndr-checker --config /app/config/targets.yaml --output-dir /app/output
```

### 5. View Results

Reports are written to `output/`:
- `output/latest.json` – Latest check results (JSON)
- `output/report_YYYYMMDD_HHMMSS.json` – Timestamped JSON report
- `output/report_YYYYMMDD_HHMMSS.csv` – Timestamped CSV report
- Console output shows a summary table

## Configuration Reference

The config file is YAML format. See `config/targets.example.yaml` for a full example.

### Global Defaults

```yaml
defaults:
  timeout: 10                  # Request timeout in seconds (default: 10)
  retries: 2                   # Number of retries on failure (default: 2)
  verify_tls: true             # Verify TLS certificates (default: true)
  expected_status:             # HTTP status codes that indicate "UP"
    - 200                      # (default: [200, 301, 302, 303, 307, 308, 401, 403])
    - 301
    - 401
    - 403
  workers: 10                  # Concurrent worker threads (default: 10)
  cert_warn_days: 30           # Days until cert expiry to warn (default: 30)
  response_warn_ms: 5000       # Response time threshold for warning (default: 5000 ms)
  proxy: null                  # Optional HTTP proxy (format: http://host:port)
```

### Target Configuration

Each target must have:
- `client` (string, required) – Client/organization name
- `name` (string, required) – Human-readable console name
- `url` (string, required) – HTTPS URL to check
- `vendor` (string, optional) – Vendor name (e.g., ExtraHop, Darktrace, Vectra, Corelight)
- `verify_tls` (bool, optional) – Whether to verify TLS certificates (many consoles use self-signed certs)
- `expected_status` (list, optional) – HTTP status codes that indicate the console is up
- `timeout` (int, optional) – Request timeout in seconds
- `tags` (list, optional) – Tags for filtering targets
- `proxy` (string, optional) – Proxy URL for this target

### Example Configuration

```yaml
defaults:
  timeout: 10
  retries: 2
  verify_tls: true
  expected_status: [200, 301, 302, 303, 307, 308, 401, 403]
  workers: 10
  cert_warn_days: 30
  response_warn_ms: 5000

targets:
  - client: "ACME Corp"
    name: "ExtraHop Production"
    vendor: "ExtraHop"
    url: "https://extrahop.acme.com"
    verify_tls: true
    tags:
      - production
      - tier1

  - client: "ACME Corp"
    name: "ExtraHop Dev"
    vendor: "ExtraHop"
    url: "https://extrahop-dev.acme.com:8443"
    verify_tls: false          # Self-signed certificate
    timeout: 15
    tags:
      - development

  - client: "Beta Industries"
    name: "Darktrace Console"
    vendor: "Darktrace"
    url: "https://darktrace.beta-ind.com"
    verify_tls: true
```

## CLI Usage

```
python -m ndr_checker [OPTIONS]

Options:
  --config PATH           Path to YAML config file (required)
  --output-dir PATH       Output directory for reports (default: output)
  --workers N             Number of concurrent workers (default: 10)
  --only-client NAME      Only check targets for this client
  --tag TAG               Only check targets with this tag (repeatable)
  --verbose               Enable debug logging
```

### Examples

Check all targets:
```bash
python -m ndr_checker --config config/targets.yaml --output-dir output
```

Check only "ACME Corp" targets:
```bash
python -m ndr_checker --config config/targets.yaml --only-client "ACME Corp"
```

Check only production targets:
```bash
python -m ndr_checker --config config/targets.yaml --tag production
```

Check with debug logging:
```bash
python -m ndr_checker --config config/targets.yaml --verbose
```

Use 5 concurrent workers:
```bash
python -m ndr_checker --config config/targets.yaml --workers 5
```

## Exit Codes

The tool exits with the highest severity code encountered:

- `0` – All targets are `UP`
- `1` – At least one target is `WARN` (cert expiring soon or slow response)
- `2` – At least one target is `DOWN` (unreachable or error)
- `3` – Configuration error (missing file, invalid YAML, etc.)

Use these codes in wrapper scripts to trigger alerts or take action.

## Scheduling

### Cron (Ubuntu/Linux)

Add to your crontab (`crontab -e`):

```bash
# Run health checks on weekdays at 07:30, log to file
30 7 * * 1-5 /usr/local/bin/ndr-checker.sh >> /var/log/ndr-checker.log 2>&1
```

Create `/usr/local/bin/ndr-checker.sh`:

```bash
#!/bin/bash
cd /opt/ndr-checker
docker run --rm \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/output:/app/output \
  -e WEBHOOK_URL="${WEBHOOK_URL:-}" \
  ndr-checker --config /app/config/targets.yaml --output-dir /app/output

exit_code=$?
if [ $exit_code -ge 2 ]; then
  echo "Health check failed with exit code $exit_code" | mail -s "NDR Health Check Alert" ops@example.com
fi

exit $exit_code
```

### Systemd Timer

Create `/etc/systemd/system/ndr-checker.service`:

```ini
[Unit]
Description=NDR Console Health Check
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=/opt/ndr-checker
ExecStart=/usr/local/bin/ndr-checker.sh
Environment="WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
StandardOutput=journal
StandardError=journal
```

Create `/etc/systemd/system/ndr-checker.timer`:

```ini
[Unit]
Description=Run NDR Health Checks Daily
Requires=ndr-checker.service

[Timer]
OnCalendar=Mon-Fri 07:30
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:

```bash
sudo systemctl enable ndr-checker.timer
sudo systemctl start ndr-checker.timer
sudo systemctl status ndr-checker.timer
```

View logs:

```bash
journalctl -u ndr-checker.service -f
```

## Webhooks (Teams / Slack)

Set the `WEBHOOK_URL` environment variable to send notifications to Teams or Slack:

```bash
export WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
docker run --rm \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/output:/app/output \
  -e WEBHOOK_URL="$WEBHOOK_URL" \
  ndr-checker --config /app/config/targets.yaml --output-dir /app/output
```

Notifications are sent **only if at least one target is DOWN or WARN**. The payload is compatible with Teams and Slack incoming webhooks.

To generate a Slack webhook:
1. Go to your Slack workspace
2. Create or select a channel
3. Add an "Incoming Webhooks" app
4. Copy the webhook URL and set it as `WEBHOOK_URL`

## Certificate Verification

By default, the tool verifies TLS certificates. However, many NDR consoles use self-signed certificates. You can disable verification per target:

```yaml
targets:
  - client: "Example"
    name: "Self-Signed Console"
    url: "https://console.example.com"
    verify_tls: false          # Skip certificate verification
```

**Note**: The tool always performs the TLS handshake and reads the certificate expiry date, even when `verify_tls: false`. This ensures you still get certificate expiry warnings.

## Handling Custom CAs

If your consoles use internal CAs, you can mount a custom CA bundle:

```bash
docker run --rm \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/output:/app/output \
  -v /path/to/ca-bundle.crt:/etc/ssl/certs/ca-bundle.crt:ro \
  -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt \
  ndr-checker --config /app/config/targets.yaml --output-dir /app/output
```

## Output Permissions

The Docker image runs as non-root user `app` (UID 1000). Ensure the output directory is writable:

```bash
mkdir -p output
chmod 755 output
```

Or pre-create with correct ownership:

```bash
docker run --rm -v $(pwd)/output:/app/output ndr-checker:latest mkdir -p /app/output
```

## Troubleshooting

### Config file not found

```
Error: Config file not found: config/targets.yaml
```

**Solution**: Ensure the config file exists and the path is correct. Use absolute paths in Docker:

```bash
docker run --rm \
  -v $(pwd)/config:/app/config:ro \
  ndr-checker --config /app/config/targets.yaml
```

### Invalid YAML

```
Error: Configuration error: Name required field: name
```

**Solution**: Check your YAML syntax and ensure all required fields are present. Use a YAML validator:

```bash
python -m yaml config/targets.yaml
```

### "Cannot write output directory"

```
Error: Permission denied: output/report_20231101_143022.json
```

**Solution**: Ensure the output directory is writable by the `app` user (UID 1000):

```bash
chmod 755 output
```

### TLS certificate errors

If you see "certificate verify failed" but the console is reachable, set `verify_tls: false` for that target:

```yaml
targets:
  - client: "Example"
    name: "Console with Self-Signed Cert"
    url: "https://console.example.com"
    verify_tls: false
```

### Firewall / Network Access

The automation server's source IP may need to be allow-listed on client firewalls. Ensure the server running the Docker container can reach the console URLs on port 443 (or custom ports).

## Development

### Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run checks locally
python -m ndr_checker --config config/targets.yaml --output-dir output --verbose
```

### Running in Verbose Mode

Enable debug logging to see detailed check output:

```bash
python -m ndr_checker --config config/targets.yaml --verbose
docker run --rm \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/output:/app/output \
  ndr-checker --config /app/config/targets.yaml --verbose
```

## Repository Structure

```
.
├── CLAUDE.md                    # Project specification
├── README.md                    # This file
├── Dockerfile                   # Docker image definition
├── .dockerignore                # Docker build excludes
├── .gitignore                   # Git excludes
├── requirements.txt             # Python dependencies
├── config/
│   └── targets.example.yaml     # Example configuration (committed)
├── ndr_checker/
│   ├── __init__.py
│   ├── __main__.py              # CLI entry point
│   ├── config.py                # Config loading and validation
│   ├── checks.py                # DNS, TCP, TLS, HTTPS checks
│   ├── runner.py                # Concurrent execution with retries
│   ├── report.py                # Report generation (console, JSON, CSV)
│   └── notify.py                # Webhook notifications
└── tests/
    └── test_checks.py           # Unit tests
```

## License

See LICENSE file.
