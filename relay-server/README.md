# HTTP-01 ACME Challenge Relay Server

> **Security hold (2026-10-13): do not deploy or restart the published `latest`
> image.** It is vulnerable to SSRF. The local source changes are an **undeployed
> hardening draft**, not a released image. Historical run/Compose instructions
> below do not configure the draft and must not be used to restore service.
>
> The draft requires `ALLOWED_GATEWAY_DOMAINS` containing exact approved gateway
> bases. CNAME must exactly equal `_.<approved-base>` (DNS case/root-dot normalized).
> Regex extraction and fallback are removed; missing/unmatched CNAME is rejected.
> There is no incoming custom-domain registration requirement.
> It serves GET/HEAD only at
> `/.well-known/acme-challenge/<base64url-token>`; the token must be 22–256 bytes.
> TXT app IDs must be 40 lowercase hexadecimal characters with a numeric nonzero
> port; the port remains ignored as before (gateway default guest HTTP port 80).
> Arbitrary paths, app-ID port selectors, redirect mode, upstream redirects and
> non-public destination IPs are rejected. Incoming forwarding headers are ignored.
> Only the validated custom Host is forwarded. Health and metrics remain local
> relay endpoints, never proxies.
>
> Before any approved deployment: inventory legacy HTTP-01 tenants, test their
> challenge responders, pass the new policy environment variable, bind the host
> listener to loopback behind nginx, add egress controls, pin a reviewed image
> digest, and verify a reproducible container build. The current Dockerfile uses
> Rust 1.83 with unlocked dependencies; the local test run used Rust 1.95 and is
> not proof that the Dockerfile builds. Node-ops automation quarantine is tracked
> separately. Prefer DNS-01 or suitable TLS-ALPN-01 migration over restoration.

A Rust-based relay server that receives HTTP-01 ACME challenges on port 80, performs DNS lookups, and redirects to dstack applications running on HTTPS.

## How It Works

### Protocol Flow

1. ACME client generates challenge and serves it at `https://{app-id}.{gateway-domain}/.well-known/acme-challenge/{token}`
2. Let's Encrypt requests `http://{custom-domain}/.well-known/acme-challenge/{token}`
3. This relay server:
   - Looks up `TXT _dstack-app-address.{custom-domain}` → gets `{app-id}:port`
   - Looks up `CNAME {custom-domain}` → gets `_.{gateway-base-domain}`
   - Redirects to `https://{app-id}.{gateway-domain}/.well-known/acme-challenge/{token}`
4. Let's Encrypt follows the redirect and validates the challenge

## DNS Configuration

For each custom domain, configure:

```
TXT _dstack-app-address.{custom-domain}  {app-id}:port
CNAME {custom-domain}                    _.{gateway-base-domain}
```

Example:
```
TXT _dstack-app-address.http01-test.phala.systems  my-app-123:80
CNAME http01-test.phala.systems                    _.prod5.phala.network
```

## Building and Running

### Local Development

```bash
# Configure environment variables
cp .env.example .env
# Edit .env with your settings

# Build
cargo build --release

# Run (requires sudo for port 80)
sudo -E ./target/release/relay-server

# Or run in development mode
cargo run
```

**Note**: Use `sudo -E` to preserve environment variables when running as root.

### Docker

**Pull and run:**
```bash
# Pull the pre-built image
docker pull h4x3rotab/dstack-http01-relay-server:latest

# Run on port 8081 (recommended)
docker run -d \
  --name relay-server \
  --restart unless-stopped \
  -p 8081:8081 \
  -e FALLBACK_GATEWAY_DOMAIN=prod5.phala.network \
  h4x3rotab/dstack-http01-relay-server:latest

# Run on port 80 (requires privileged port binding)
docker run -d \
  --name relay-server \
  --restart unless-stopped \
  -p 80:80 \
  -e PORT=80 \
  -e FALLBACK_GATEWAY_DOMAIN=prod5.phala.network \
  h4x3rotab/dstack-http01-relay-server:latest
```

**Using docker-compose:**

The repository includes docker-compose configurations:
- `docker-compose.yml` - Basic setup (port 8081)
- `docker-compose.nginx.yml` - With nginx proxy (port 80)

```bash
# Basic setup
docker-compose up -d

# With nginx proxy (recommended for production)
docker-compose -f docker-compose.nginx.yml up -d

# View logs
docker-compose logs -f relay-server

# Stop
docker-compose down
```

**Build locally:**
```bash
docker build -t h4x3rotab/dstack-http01-relay-server:latest .
```

### Production Deployment

**Requirements:**
- Machine reachable from the internet on port 80
- DNS resolution capability

**Recommended setup (using docker-compose with nginx):**
```bash
# Use the nginx compose file for production
docker-compose -f docker-compose.nginx.yml up -d
```

This configuration:
- Runs relay server on port 8081 internally
- Uses nginx to proxy port 80 to the relay server
- Preserves the Host header (critical for DNS lookups)
- Includes health checks and logging

**Alternative (direct port 80):**
```bash
docker run -d \
  --name relay-server \
  --restart unless-stopped \
  -p 80:80 \
  -e PORT=80 \
  -e FALLBACK_GATEWAY_DOMAIN=prod5.phala.network \
  h4x3rotab/dstack-http01-relay-server:latest
```

## Configuration

### Environment Variables

- **`FALLBACK_GATEWAY_DOMAIN`** (optional): Fallback gateway domain to use when CNAME lookup fails or doesn't match the allowed regex
  - Example: `prod5.phala.network`

- **`ALLOWED_DOMAIN_REGEX`** (optional): Regex pattern to match and extract gateway domain from CNAME records
  - Default: `^_\.(.+\.phala\.network)$`
  - Use capture groups to extract the gateway domain (see `GATEWAY_DOMAIN_CAPTURE_GROUP`)
  - Examples:
    - `^_\.(.+\.phala\.network)$` - Matches `_.prod5.phala.network` with group 1 = `prod5.phala.network`
    - `^(.+)\.phala\.network$` - Matches `prod5.phala.network` with group 1 = `prod5`
    - `^_\.(.+?)\.(.+)$` - Matches `_.prod5.phala.network` with group 1 = `prod5`, group 2 = `phala.network`

- **`GATEWAY_DOMAIN_CAPTURE_GROUP`** (optional): Which capture group from the regex to use as gateway domain
  - Default: `1`
  - Example: Set to `2` to use the second capture group, `0` to use the entire match

- **`RUST_LOG`** (optional): Logging level
  - Examples: `relay_server=info`, `relay_server=debug`, `relay_server=trace`

## Endpoints

- `/.well-known/acme-challenge/:token` - ACME challenge relay endpoint
- `/metrics` - Prometheus metrics
- `/health` - Health check endpoint
- `/` - Server information

## Monitoring

The server exposes Prometheus metrics at `/metrics`:

- `http_requests_total` - Total HTTP requests by method, path, and status
- `http_request_duration_seconds` - Request duration histogram
- `dns_lookups_total` - DNS lookup counts by type and status
- `redirects_total` - Total redirects by status

Example Prometheus scrape config:
```yaml
scrape_configs:
  - job_name: 'relay-server'
    static_configs:
      - targets: ['relay-server:80']
```

## Logging

Set the `RUST_LOG` environment variable to control logging:

```bash
# Info level (default)
RUST_LOG=relay_server=info

# Debug level
RUST_LOG=relay_server=debug

# Trace level for detailed debugging
RUST_LOG=relay_server=trace,tower_http=debug
```

## Testing

```bash
# Run unit tests
cargo test

# Health check
curl http://localhost:8081/health

# Test the server manually (requires DNS records to be set)
curl -v http://localhost:8081/.well-known/acme-challenge/test-token \
  -H "Host: http01-test.phala.systems"

# Expected: 307 Temporary Redirect to dstack HTTPS URL
```

## Security Considerations

- The server performs DNS lookups on untrusted input (custom domains)
- DNS responses should be validated and sanitized
- Consider rate limiting for DNS lookups
- Monitor for DNS lookup failures and abuse

## License

See main project LICENSE file.
