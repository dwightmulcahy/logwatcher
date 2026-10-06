# logwatcher

Logwatch is a nightly sidecar container that reads a web app's Docker logs, checks errors, latency, uptime gaps and probes, sorts users from search, AI and spoofed bots using published IP ranges, compares against a 14-day baseline, and emails an HTML report, calling Claude for analysis only when something is flagged.

## What it checks

| Area | Details |
|---|---|
| Availability | Container not running, restarts, OOM kills, gaps in health checks, no log lines at all |
| Errors | 5xx responses, tracebacks and other non-JSON output, app messages logged at ERROR/CRITICAL |
| Latency | Health-check p50/p95/max, requests slower than `SLOW_REQUEST_MS` |
| Traffic | Users, search crawlers, AI crawlers, uptime monitors, bots, unknown; top paths, clients and user agents |
| Security | Probes (`/.env`, `/wp-admin`, `../`, ...), crawlers with a spoofed user agent (outside the provider's published IP ranges or failing forward-confirmed reverse DNS) |
| Trends | Every daily metric against a 14-day baseline (z-score), once 7 days of history exist |

Your own traffic is left out: the public IP of the machine running logwatch (your home IP, re-checked hourly, IPv6 by /64), LAN addresses, and anything in `IGNORE_IPS`.

Known-bot IP ranges come from [ipverse/bot-ip-blocks](https://github.com/ipverse/bot-ip-blocks) (official provider feeds), refreshed daily and cached in `/data`. A small built-in Google/Bing list is used if the feed can't be reached.

## Report modes

| `MODE` | Behaviour |
|---|---|
| `rules` | Rule engine only. No API key needed, no cost. |
| `claude` | Claude writes the analysis every night. |
| `hybrid` (default) | Rule report when nothing is flagged; Claude is called only on a WARN or ATTENTION flag. If the Claude call fails, the rule report is sent. |

The email is HTML (status banner, KPI tiles, flags, Claude analysis, traffic bar, tables) with a plain-text copy included. The subject reads `[<APP_NAME>] <date> ALL CLEAR` or `... ATTENTION - <reason>`. If a run itself fails, a `logwatch FAILED` email with the traceback is sent.

## Log format

The target container must write one JSON object per line to stdout:

```json
{"timestamp": "2026-10-03T14:51:06+00:00", "level": "INFO", "method": "GET", "path": "/", "status_code": 200, "duration_ms": 2.1, "client": "203.0.113.7", "user_agent": "Mozilla/5.0 ...", "api_key": null}
```

- `client` must be the real visitor IP. Behind Cloudflare, take it from `CF-Connecting-IP`, otherwise every visitor looks like Cloudflare.
- Lines without `path` are treated as app messages: `ERROR`/`CRITICAL` are flagged, the rest counted as info.
- Uvicorn's startup/shutdown lines are recognised and ignored. Any other non-JSON line is flagged.

## Setup (QNAP / any Docker host)

The image is `dwightmulcahy/logwatcher` on Docker Hub (amd64 and arm64).

1. Copy `.env.example` to `.env`, fill it in, `chmod 600 .env`.
2. Create a data folder per watched app, e.g. `mkdir -p /share/Data/config/<app>/logwatch-data`.
3. Add a service based on [`example.docker-compose.yaml`](example.docker-compose.yaml) and deploy.
4. Check `docker logs -f <logwatch container>`: it prints `logwatch <version>: watching ...`, then `mode=... STATUS: ...` and `next run ...`. Wait for the test email.
5. Set `RUN_ON_START=0` and redeploy, otherwise every restart or NAS reboot sends another report.

To watch several apps, run one logwatch service per app, each with its own `TARGET_CONTAINER`, `APP_NAME` and `/data` folder. They can share the `.env`.

To try local changes without building an image, mount your copy over the script (`/path/logwatch.py:/app/logwatch.py:ro`). Keep that file `chmod 644`: the container has the Docker socket, so whoever can edit the script can run code as root on the host.

## Releasing

Commits follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:` ...), which drive both the version number and the release notes.

- **Actions → Release → Run workflow:** leave the version empty and it is computed from the commits since the last tag (`feat` → minor, `fix` and others → patch, `type!:` or `BREAKING CHANGE` → major), or type one like `v1.4.0`.
- **Or push a tag:** `git tag v1.4.0 && git push origin v1.4.0`.

The workflow lints the script, builds a multi-arch image, pushes `X.Y.Z`, `X.Y` and `latest` (only for the newest version) to Docker Hub, smoke-tests it, and creates a GitHub Release with notes grouped by commit type. It needs the repo secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.

Preview locally: `python3 scripts/release_notes.py next` and `python3 scripts/release_notes.py notes <tag>`.

## Settings

### Per app

| Variable | Default | Purpose |
|---|---|---|
| `TARGET_CONTAINER` | `brewwatersolver` | Container whose logs are read |
| `APP_NAME` | `brewwatersolver` | Name in the subject, banner and Claude prompt |
| `APP_DESC` | homebrew water-chemistry app | One-line description given to Claude |
| `PROBE_IGNORE` | (none) | Regex of paths that look like probes but are legitimate, e.g. `^/admin$` |
| `HEALTH_PATH` | `/healthz` | Health-check path; its healthy hits are summarised, not listed |

### Schedule and delivery

| Variable | Default | Purpose |
|---|---|---|
| `TZ` | `America/Costa_Rica` | Time zone for the schedule and report |
| `RUN_AT` | `06:00` | Daily run time (24h, local) |
| `RUN_ON_START` | `0` | `1` = also run once when the container starts |
| `SEND_IF_CLEAR` | `1` | `0` = email only when something is flagged |
| `MODE` | `hybrid` | `rules`, `claude` or `hybrid` |
| `WINDOW_HOURS` | `24` | Hours covered per report |
| `MAX_CATCHUP_HOURS` | `72` | After downtime, cover missed nights up to this many hours |

### Secrets (`.env`)

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Claude API key ([get one](https://platform.claude.com/settings/keys)); API usage is billed separately from a Claude subscription |
| `ANTHROPIC_MODEL` | Default `claude-sonnet-5-5`; `claude-haiku-4-5-20251001` is cheaper |
| `SMTP_HOST`, `SMTP_PORT` | Default `smtp.gmail.com`, `587` (STARTTLS) |
| `SMTP_USER`, `SMTP_PASS` | Sender account; Gmail needs an App Password |
| `MAIL_TO` | Recipient |

### Own traffic

| Variable | Default | Purpose |
|---|---|---|
| `AUTO_IGNORE_HOME` | `1` | Detect and ignore this host's public IP(s) |
| `AUTO_IGNORE_LAN` | `1` | Ignore private/LAN client addresses |
| `IGNORE_IPS` | (none) | Extra comma-separated IPs to ignore (phone carrier, office, VPN) |
| `HOME_IP_URLS` | ipify v4 + v6 | Services that return the public IP |
| `HOME_IP_CHECK_MIN` | `60` | How often the home IP is re-checked |

### Thresholds

| Variable | Default | Purpose |
|---|---|---|
| `HEALTH_GAP_S` | `90` | Gap between health checks counted as downtime |
| `HEALTH_SLOW_MS` | `50` | Health checks slower than this are listed |
| `HEALTH_P95_WARN_MS` | `25` | WARN when health p95 exceeds this |
| `SLOW_REQUEST_MS` | `500` | WARN on requests at or above this |
| `BASELINE_DAYS` | `14` | Days of history in the baseline |
| `BASELINE_MIN_DAYS` | `7` | Days needed before baseline checks start |
| `Z_THRESHOLD` | `3` | Standard deviations above the mean that trigger a WARN |
| `Z_MIN_ABS` | `5` | Minimum absolute increase over the mean that triggers a WARN |
| `MAX_LINES` | `1500` | Log lines sent to Claude (middle trimmed beyond this) |

### Bot detection

| Variable | Default | Purpose |
|---|---|---|
| `BOT_FEEDS` | ipverse `crawlers.json`, `monitoring.json` | Comma-separated feed URLs |
| `BOT_FEED_MAX_AGE_H` | `24` | Feed refresh interval |
| `VERIFY_RDNS` | `1` | Forward-confirmed reverse DNS for crawlers without a published IP list |

### Files

| Variable | Default | Purpose |
|---|---|---|
| `STATE_FILE` | `/data/state.json` | Baseline history, last run, restart tracking, home IPs |
| `BOT_FEED_CACHE` | `/data/bot_ranges.json` | Cached bot ranges |

## Notes

- `docker logs` only reaches back to when the container was created. After a redeploy (e.g. Watchtower) the report says how many hours the logs cover, and days with under 80% coverage are kept out of the baseline.
- Mounting `/var/run/docker.sock` gives the container root-equivalent access to the host, even with `:ro`.
- Cost in `hybrid` mode is a few cents on nights when something is flagged and nothing otherwise.
