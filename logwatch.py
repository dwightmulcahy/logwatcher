"""Nightly log analyzer for self-hosted web apps (brewwatersolver, mhb-web, ...).

docker logs -> digest -> rule checks (+14-day baseline) -> optional Claude report -> email.
MODE: rules (no API), claude (always), hybrid (Claude only when a rule flags WARN/ATTENTION).
Per-app settings: TARGET_CONTAINER, APP_NAME, APP_DESC, PROBE_IGNORE.
"""
import collections
import datetime as dt
import fnmatch
import html as html_lib
import ipaddress
import json
import os
import re
import smtplib
import socket
import statistics
import time
import traceback
import urllib.request
from email.message import EmailMessage
from zoneinfo import ZoneInfo

import docker

VERSION = os.getenv("LOGWATCH_VERSION", "dev")
TZ = ZoneInfo(os.getenv("TZ", "America/Costa_Rica"))
CONTAINER = os.getenv("TARGET_CONTAINER", "brewwatersolver")
MODE = os.getenv("MODE", "hybrid").lower()
RUN_AT = os.getenv("RUN_AT", "06:00")
WINDOW_HOURS = int(os.getenv("WINDOW_HOURS", "24"))
MAX_CATCHUP_HOURS = int(os.getenv("MAX_CATCHUP_HOURS", "72"))
MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
MAX_LINES = int(os.getenv("MAX_LINES", "1500"))
STATE_FILE = os.getenv("STATE_FILE", "/data/state.json")
SEND_IF_CLEAR = os.getenv("SEND_IF_CLEAR", "1") == "1"

# Per-app identity (defaults keep the original brewwatersolver behaviour)
APP = os.getenv("APP_NAME", "brewwatersolver")
APP_DESC = os.getenv("APP_DESC", "a homebrew water-chemistry web app (JSON request logs)")
# Paths that match PROBE_RE but are legitimate for this app, e.g. ^/admin$ (default matches nothing)
PROBE_IGNORE = re.compile(os.getenv("PROBE_IGNORE", r"(?!)"))

HEALTH_PATH = os.getenv("HEALTH_PATH", "/healthz")
HEALTH_SLOW_MS = float(os.getenv("HEALTH_SLOW_MS", "50"))
HEALTH_GAP_S = float(os.getenv("HEALTH_GAP_S", "90"))
HEALTH_P95_WARN_MS = float(os.getenv("HEALTH_P95_WARN_MS", "25"))
SLOW_REQUEST_MS = float(os.getenv("SLOW_REQUEST_MS", "500"))

BASELINE_DAYS = int(os.getenv("BASELINE_DAYS", "14"))
BASELINE_MIN_DAYS = int(os.getenv("BASELINE_MIN_DAYS", "7"))
Z_THRESHOLD = float(os.getenv("Z_THRESHOLD", "3"))
Z_MIN_ABS = float(os.getenv("Z_MIN_ABS", "5"))
HISTORY_KEEP = 60

PROBE_RE = re.compile(
    r"(\.env|\.git|\.aws|\.ssh|wp-|wordpress|xmlrpc|phpmyadmin|\.php|cgi-bin|/admin|/actuator|"
    r"server-status|/vendor/|\.\./|%2e%2e|/etc/passwd|\.sql|\.bak|config\.(json|yml|yaml))",
    re.I,
)
# Known-bot IP ranges: ipverse/bot-ip-blocks (official provider feeds, normalized: CIDRs,
# UA patterns, rDNS patterns). Cached in /data; refreshed every BOT_FEED_MAX_AGE_H.
BOT_FEEDS = os.getenv(
    "BOT_FEEDS",
    "https://raw.githubusercontent.com/ipverse/bot-ip-blocks/master/crawlers.json,"
    "https://raw.githubusercontent.com/ipverse/bot-ip-blocks/master/monitoring.json",
).split(",")
BOT_FEED_CACHE = os.getenv("BOT_FEED_CACHE", "/data/bot_ranges.json")
BOT_FEED_MAX_AGE_H = float(os.getenv("BOT_FEED_MAX_AGE_H", "24"))
VERIFY_RDNS = os.getenv("VERIFY_RDNS", "1") == "1"
AI_BOTS = {"GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "PerplexityBot", "Amazonbot",
           "Meta-ExternalAgent", "Common Crawl"}
SEO_BOTS = {"Ahrefs", "SE Ranking", "SERankingBacklinksBot"}
# Fallback when the feed is unreachable and nothing is cached.
FALLBACK_SERVICES = {
    "Googlebot": {"ipv4": ["66.249.64.0/19"], "user_agent_patterns": ["*googlebot*"],
                  "rdns_patterns": ["*.googlebot.com", "*.google.com"], "ip_list_authoritative": True},
    "Bingbot": {"ipv4": ["40.77.0.0/16", "157.55.0.0/16", "207.46.0.0/16", "52.167.144.0/24"],
                "user_agent_patterns": ["*bingbot*"], "rdns_patterns": ["*.search.msn.com"],
                "ip_list_authoritative": True},
}
# UA-only names for crawlers without a published IP feed (verified via rDNS if pattern known).
EXTRA_UA_SERVICES = {
    "Baiduspider": {"user_agent_patterns": ["*baiduspider*"], "rdns_patterns": ["*.baidu.com", "*.baidu.jp"]},
    "Yahoo": {"user_agent_patterns": ["*slurp*"], "rdns_patterns": ["*.crawl.yahoo.net"]},
}
BOT_UA_RE = re.compile(
    r"(bot|crawl|spider|scan|slurp|fetch|curl|wget|python|go-http|java/|okhttp|libwww|httpclient|"
    r"axios|node-fetch|headless|phantom|zgrab|masscan|nmap|nikto|sqlmap|nuclei|censys|shodan|"
    r"expanse|semrush|ahrefs|mj12|dotbot|petalbot|bytespider|gptbot|claudebot|ccbot|facebookexternalhit)",
    re.I,
)
BENIGN_LINE_RE = re.compile(
    r"^INFO:\s+(Started server process|Waiting for application|Application startup complete|"
    r"Uvicorn running on|Shutting down|Waiting for application shutdown|Application shutdown complete|"
    r"Finished server process)"
)
IGNORE_IPS = {ip.strip() for ip in os.getenv("IGNORE_IPS", "").split(",") if ip.strip()}
# Auto-detect home: logwatch runs on the NAS, so its public egress IP is the home IP.
# Checked hourly (dynamic IPs change); every IP seen during the report window is ignored.
AUTO_IGNORE_HOME = os.getenv("AUTO_IGNORE_HOME", "1") == "1"
AUTO_IGNORE_LAN = os.getenv("AUTO_IGNORE_LAN", "1") == "1"  # 192.168.x etc. = direct LAN access
HOME_IP_URLS = os.getenv("HOME_IP_URLS", "https://api.ipify.org,https://api6.ipify.org").split(",")
HOME_IP_CHECK_MIN = int(os.getenv("HOME_IP_CHECK_MIN", "60"))
HOME_IPS = set()  # set per run
TRAFFIC_CLASSES = ("user", "search_crawler", "ai_crawler", "monitor", "bot", "unknown")
SEVERITY_ORDER = {"ATTENTION": 2, "WARN": 1, "INFO": 0}

SYSTEM_PROMPT = f"""You analyze access/application logs for "{APP}", {APP_DESC}, \
self-hosted in Docker on a home QNAP NAS and reachable \
from the internet. Healthy /healthz 200s were removed and summarized as stats; health-check gaps \
indicate downtime. Rule-engine flags and a 14-day baseline are included; verify and explain them.

Write a terse plain-text report, no pleasantries. First line exactly: "STATUS: ALL CLEAR" or \
"STATUS: ATTENTION - <reason>". Then sections:
1. Errors & availability (5xx, exceptions, non-JSON lines, restarts, health gaps)
2. Latency (health stats, slow requests)
3. Traffic (search crawlers vs generic bots vs likely users; top paths; API key usage; vs baseline)
4. Security (probes, repeat offenders by IP)
5. Actions (only concrete ones; "None" if nothing)
Do not invent data."""


# ---------- state ----------
def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {"history": []}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, STATE_FILE)


# ---------- collection ----------
def collect(since_ts: int):
    container = docker.from_env().containers.get(CONTAINER)
    raw = container.logs(since=since_ts, stdout=True, stderr=True)
    state = container.attrs["State"]
    meta = {
        "status": state.get("Status"),
        "started_at": state.get("StartedAt"),
        "restart_count": container.attrs.get("RestartCount"),
        "oom_killed": state.get("OOMKilled"),
        "image": container.attrs["Config"]["Image"],
    }
    return raw.decode("utf-8", "replace").splitlines(), meta


def _ts(value):
    try:
        return dt.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


# ---------- known-bot ranges ----------
class BotDB:
    def __init__(self, services: dict, source: str):
        self.source = source
        self.services = {**EXTRA_UA_SERVICES, **services}
        self.nets = []  # (network, service name, category)
        self.ua = []    # (lowercase glob, service name)
        for name, svc in self.services.items():
            category = svc.get("_category", "crawlers")
            for cidr in svc.get("ipv4", []) + svc.get("ipv6", []):
                try:
                    self.nets.append((ipaddress.ip_network(cidr, strict=False), name, category))
                except ValueError:
                    pass
            for pat in svc.get("user_agent_patterns", []):
                self.ua.append((pat.lower(), name))
        self._ip_cache = {}

    def lookup_ip(self, ip):
        if ip not in self._ip_cache:
            hit = None
            try:
                addr = ipaddress.ip_address(ip)
                hit = next(((n, c) for net, n, c in self.nets if addr in net), None)
            except (ValueError, TypeError):
                pass
            self._ip_cache[ip] = hit
        return self._ip_cache[ip]

    def lookup_ua(self, ua):
        low = ua.lower()
        return next((name for pat, name in self.ua if fnmatch.fnmatchcase(low, pat)), None)

    def category(self, name, feed_category):
        if feed_category == "monitoring":
            return "monitor"
        if name in AI_BOTS:
            return "ai_crawler"
        if name in SEO_BOTS:
            return "bot"
        return "search_crawler"


def _fetch_feeds():
    services = {}
    for url in BOT_FEEDS:
        with urllib.request.urlopen(url.strip(), timeout=20) as resp:
            data = json.load(resp)["services"]
        category = "monitoring" if "monitor" in url else "crawlers"
        for name, svc in data.items():
            services[name] = {**svc, "_category": category}
    return services


def load_bot_db():
    cached = None
    try:
        with open(BOT_FEED_CACHE) as f:
            cached = json.load(f)
    except (FileNotFoundError, ValueError):
        pass
    fresh = cached and time.time() - cached.get("fetched_at", 0) < BOT_FEED_MAX_AGE_H * 3600
    if not fresh:
        try:
            cached = {"fetched_at": time.time(), "services": _fetch_feeds()}
            os.makedirs(os.path.dirname(BOT_FEED_CACHE), exist_ok=True)
            with open(BOT_FEED_CACHE + ".tmp", "w") as f:
                json.dump(cached, f)
            os.replace(BOT_FEED_CACHE + ".tmp", BOT_FEED_CACHE)
        except Exception as ex:
            print(f"bot feed refresh failed: {ex}", flush=True)
    if cached and cached.get("services"):
        age_h = (time.time() - cached["fetched_at"]) / 3600
        return BotDB(cached["services"], f"ipverse feed, {age_h:.0f}h old")
    return BotDB(FALLBACK_SERVICES, "built-in fallback (feed unavailable)")


_rdns_cache = {}


def rdns_verified(ip, patterns):
    """Forward-confirmed reverse DNS: PTR matches a pattern and resolves back to the same IP."""
    if not VERIFY_RDNS or not patterns:
        return None
    key = (ip, tuple(patterns))
    if key not in _rdns_cache:
        ok = False
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3)
        try:
            host = socket.gethostbyaddr(ip)[0].lower()
            if any(fnmatch.fnmatchcase(host, p.lower()) for p in patterns):
                ok = ip in {ai[4][0] for ai in socket.getaddrinfo(host, None)}
        except socket.herror:  # no PTR record: not the claimed bot
            ok = False
        except (OSError, UnicodeError):  # DNS timeout/outage: can't tell
            ok = None
        finally:
            socket.setdefaulttimeout(old)
        _rdns_cache[key] = ok
    return _rdns_cache[key]


BOTS = None  # set per run


# ---------- own traffic ----------
def refresh_home_ips(state):
    """Record the current public IP(s) with a last-seen time; keep 7 days."""
    if not AUTO_IGNORE_HOME:
        return
    now = dt.datetime.now(dt.timezone.utc)
    seen = state.setdefault("home_ips", {})
    for url in HOME_IP_URLS:
        try:
            with urllib.request.urlopen(url.strip(), timeout=5) as resp:
                ip = str(ipaddress.ip_address(resp.read().decode().strip()))
            seen[ip] = now.isoformat()
        except Exception:
            pass  # no IPv6, or service down: keep last known values
    cutoff = now - dt.timedelta(days=7)
    state["home_ips"] = {ip: t for ip, t in seen.items() if (_ts(t) or now) >= cutoff}


def home_ips_for_window(state, start):
    cutoff = start - dt.timedelta(hours=2)
    return {ip for ip, t in state.get("home_ips", {}).items() if (_ts(t) or cutoff) >= cutoff}


def is_own_ip(ip):
    if not ip:
        return False
    if ip in IGNORE_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if AUTO_IGNORE_LAN and addr.is_private and not addr.is_loopback:
        return True
    for home in HOME_IPS:
        h = ipaddress.ip_address(home)
        if h.version == addr.version == 4 and h == addr:
            return True
        if h.version == addr.version == 6 and addr in ipaddress.ip_network(f"{home}/64", strict=False):
            return True  # IPv6: every device at home shares the /64 prefix
    return False


def classify(ua, ip):
    """-> (class, bot_name, spoofed)."""
    hit = BOTS.lookup_ip(ip)
    if hit:  # IP inside a published range: verified regardless of UA
        name, feed_cat = hit
        return BOTS.category(name, feed_cat), name, False
    if not ua:
        return "unknown", None, False
    claimed = BOTS.lookup_ua(ua)
    if claimed:
        svc = BOTS.services.get(claimed, {})
        cat = BOTS.category(claimed, svc.get("_category"))
        if svc.get("ip_list_authoritative"):
            return cat, claimed, True  # claims bot, IP not in its official list
        verified = rdns_verified(ip, svc.get("rdns_patterns"))
        return cat, claimed, verified is False
    if BOT_UA_RE.search(ua):
        return "bot", None, False
    if ua.lower().startswith("mozilla/"):
        return "user", None, False
    return "bot", None, False


def digest(lines):
    kept, non_json_samples, hc_ms, hc_times, slow = [], [], [], [], []
    status, paths, clients, levels, probe_ips, bots = (collections.Counter() for _ in range(6))
    probes, api_keys = [], set()
    traffic, user_agents = collections.Counter(), collections.Counter()
    class_ips = collections.defaultdict(set)
    client_class, spoofs = {}, []
    non_json = benign = ignored = 0
    ignored_ips = set()

    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            entry = None
        if not isinstance(entry, dict):
            if not line.strip():
                continue
            if BENIGN_LINE_RE.search(line):  # uvicorn startup/shutdown chatter
                benign += 1
                continue
            non_json += 1
            non_json_samples.append(line)
            kept.append(line)
            continue

        client = entry.get("client")
        path, code = entry.get("path"), entry.get("status_code")
        ms = entry.get("duration_ms") or 0

        if path is None:  # app message, not a request (startup notes, crash reports)
            if str(entry.get("level", "")).upper() in ("ERROR", "CRITICAL"):
                non_json += 1
                non_json_samples.append(line)
                kept.append(line)
            else:
                benign += 1
            continue
        is_probe = bool(PROBE_RE.search(path) and not PROBE_IGNORE.search(path))

        if path == HEALTH_PATH:
            if (t := _ts(entry.get("timestamp"))):
                hc_times.append(t)
            if code == 200 and ms < HEALTH_SLOW_MS:
                hc_ms.append(ms)
                continue

        if is_own_ip(client):
            ignored += 1
            ignored_ips.add(client)
            continue
        levels[entry.get("level")] += 1

        status[code] += 1
        paths[f"{entry.get('method')} {path}"] += 1
        clients[client] += 1
        if entry.get("api_key"):
            api_keys.add(str(entry["api_key"])[:8])
        ua = entry.get("user_agent")
        cls, name, spoofed = classify(ua, client)
        if is_probe and cls in ("user", "unknown"):
            cls = "bot"  # browser UA but probing for secrets/CMS paths
        traffic[cls] += 1
        class_ips[cls].add(client)
        client_class[client] = cls
        if ua:
            user_agents[ua[:120]] += 1
        if name:
            bots[name] += 1
        if spoofed:
            spoofs.append((client, name, (ua or "")[:120]))
        if is_probe:
            probes.append((client, path, code))
            probe_ips[client] += 1
        if path != HEALTH_PATH and ms >= SLOW_REQUEST_MS:
            slow.append((path, ms))
        kept.append(line)

    hc_times.sort()
    gaps = [
        f"{a.isoformat()} -> {b.isoformat()} ({(b - a).total_seconds():.0f}s)"
        for a, b in zip(hc_times, hc_times[1:])
        if (b - a).total_seconds() > HEALTH_GAP_S
    ]
    health = {"healthy_checks": len(hc_ms), "gaps": gaps}
    if len(hc_ms) >= 2:
        q = statistics.quantiles(hc_ms, n=100)
        health.update(p50_ms=round(q[49], 2), p95_ms=round(q[94], 2), p99_ms=round(q[98], 2),
                      max_ms=round(max(hc_ms), 2))

    omitted = 0
    if len(kept) > MAX_LINES:
        omitted = len(kept) - MAX_LINES
        half = MAX_LINES // 2
        kept = kept[:half] + [f"... {omitted} lines omitted ..."] + kept[-half:]

    external = {c: n for c, n in clients.items() if c and c not in ("127.0.0.1", "::1")}
    count = lambda lo, hi: sum(v for k, v in status.items() if isinstance(k, int) and lo <= k < hi)
    summary = {
        "total_lines": len(lines),
        "non_json_lines": non_json,
        "non_json_samples": non_json_samples[:20],
        "benign_startup_lines": benign,
        "ignored_own_requests": ignored,
        "ignored_own_ips": sorted(ignored_ips),
        "home_ips": sorted(HOME_IPS),
        "levels": dict(levels),
        "status_codes": {str(k): v for k, v in status.items()},
        "top_paths": paths.most_common(25),
        "top_clients": clients.most_common(25),
        "known_bots": dict(bots),
        "traffic_classes": {c: {"requests": traffic[c], "ips": len(class_ips[c])} for c in TRAFFIC_CLASSES},
        "client_class": client_class,
        "top_user_agents": user_agents.most_common(15),
        "spoofed_crawlers": spoofs[:20],
        "probes": probes[:50],
        "probe_ips": probe_ips.most_common(10),
        "slow_requests": sorted(slow, key=lambda x: -x[1])[:20],
        "api_key_prefixes": sorted(api_keys),
        "health": health,
        "lines_omitted": omitted,
    }
    metrics = {
        "requests": sum(status.values()),
        "errors_4xx": count(400, 500),
        "errors_5xx": count(500, 600),
        "probes": len(probes),
        "unique_clients": len(external),
        "user_requests": traffic["user"],
        "user_ips": len(class_ips["user"]),
        "crawler_requests": traffic["search_crawler"],
        "ai_crawler_requests": traffic["ai_crawler"],
        "monitor_requests": traffic["monitor"],
        "bot_requests": traffic["bot"],
        "spoofed_crawlers": len(spoofs),
        "non_json": non_json,
        "health_p95_ms": health.get("p95_ms", 0),
        "health_gaps": len(gaps),
    }
    return summary, metrics, kept


# ---------- rules ----------
def evaluate(summary, metrics, meta, state, lines_total):
    flags = []
    add = lambda sev, msg: flags.append((sev, msg))
    h = summary["health"]

    if lines_total == 0:
        add("ATTENTION", "No log lines in window: container down or logging broken")
    if meta["status"] != "running":
        add("ATTENTION", f"Container status is '{meta['status']}'")
    if meta.get("oom_killed"):
        add("ATTENTION", "Container was OOM-killed")
    prev_start = state.get("started_at")
    if prev_start and meta.get("started_at") != prev_start:
        add("ATTENTION", f"Container restarted (started_at {meta.get('started_at')})")
    if metrics["errors_5xx"]:
        add("ATTENTION", f"{metrics['errors_5xx']} server errors (5xx)")
    if metrics["non_json"]:
        add("ATTENTION", f"{metrics['non_json']} non-JSON / error lines (exceptions/tracebacks?)")
    if h["gaps"]:
        add("ATTENTION", f"{len(h['gaps'])} health-check gap(s) > {HEALTH_GAP_S:.0f}s: {h['gaps'][:3]}")
    if h.get("p95_ms", 0) > HEALTH_P95_WARN_MS:
        add("WARN", f"Health p95 {h['p95_ms']} ms > {HEALTH_P95_WARN_MS:.0f} ms")
    if summary["slow_requests"]:
        add("WARN", f"{len(summary['slow_requests'])} requests >= {SLOW_REQUEST_MS:.0f} ms, "
                    f"worst {summary['slow_requests'][0]}")

    history = state.get("history", [])[-BASELINE_DAYS:]
    if len(history) >= BASELINE_MIN_DAYS:
        for key, value in metrics.items():
            past = [d["metrics"][key] for d in history if key in d["metrics"]]
            if len(past) < BASELINE_MIN_DAYS:  # metric added after history started
                continue
            mean, sd = statistics.mean(past), max(statistics.pstdev(past), 1.0)
            z = (value - mean) / sd
            if z >= Z_THRESHOLD and value - mean >= Z_MIN_ABS:
                add("WARN", f"{key}={value} is {z:.1f}σ above {len(past)}-day mean {mean:.1f}")
    else:
        add("INFO", f"Baseline building: {len(history)}/{BASELINE_MIN_DAYS} days")

    if summary["spoofed_crawlers"]:
        add("WARN", f"{len(summary['spoofed_crawlers'])} request(s) with a known-bot user agent from "
                    f"IPs outside its published ranges / failing rDNS: {', '.join(sorted({s[0] for s in summary['spoofed_crawlers']})[:5])}")
    if summary["probes"]:
        add("INFO", f"{metrics['probes']} probe requests; top IPs {', '.join(f'{ip} ({n})' for ip, n in summary['probe_ips'][:5])}")
    t = summary["traffic_classes"]
    add("INFO", f"Traffic: {t['user']['requests']} user req from {t['user']['ips']} IPs, "
                f"{t['search_crawler']['requests']} search, {t['ai_crawler']['requests']} AI, "
                f"{t['monitor']['requests']} monitor, {t['bot']['requests']} bot, "
                f"{t['unknown']['requests']} unknown")
    return sorted(flags, key=lambda f: -SEVERITY_ORDER[f[0]])


def worst(flags):
    return max((SEVERITY_ORDER[s] for s, _ in flags), default=0)


def rules_report(summary, metrics, flags, meta, start, end):
    w = worst(flags)
    head = ("STATUS: ALL CLEAR" if w == 0 else
            f"STATUS: {'ATTENTION' if w == 2 else 'WARN'} - {flags[0][1]}")
    h = summary["health"]
    out = [head, "", f"App: {APP} (container {CONTAINER})",
           f"Window: {start:%Y-%m-%d %H:%M} -> {end:%Y-%m-%d %H:%M} ({TZ.key})",
           f"Container: {meta['status']}, started {meta['started_at']}, image {meta['image']}",
           f"Bot ranges: {BOTS.source if BOTS else 'n/a'}", "",
           "FLAGS"] + [f"  [{s}] {m}" for s, m in flags] + [
        "", "METRICS"] + [f"  {k}: {v}" for k, v in metrics.items()] + [
        "", f"HEALTH: {h.get('healthy_checks')} ok, p50 {h.get('p50_ms', 'n/a')} / "
            f"p95 {h.get('p95_ms', 'n/a')} / max {h.get('max_ms', 'n/a')} ms",
        f"Startup/app info lines: {summary['benign_startup_lines']}, "
        f"ignored own requests: {summary['ignored_own_requests']} "
        f"(home IPs: {', '.join(summary['home_ips']) or 'none detected'})",
        "", "STATUS CODES: " + ", ".join(f"{k}={v}" for k, v in summary["status_codes"].items()),
        "", "TOP PATHS"] + [f"  {n:>5}  {p}" for p, n in summary["top_paths"][:10]] + [
        "", "TRAFFIC"] + [f"  {c:<15} {v['requests']:>5} req  {v['ips']:>4} IPs"
                          for c, v in summary["traffic_classes"].items()] + [
        "", "TOP CLIENTS"] + [f"  {n:>5}  {c}  {summary['client_class'].get(c, '')}"
                              for c, n in summary["top_clients"][:10]] + [
        "", "TOP USER AGENTS"] + [f"  {n:>5}  {ua}" for ua, n in summary["top_user_agents"][:10]]
    if summary["spoofed_crawlers"]:
        out += ["", "SPOOFED CRAWLERS"] + [f"  {ip}  claims {name}  {ua}" for ip, name, ua in summary["spoofed_crawlers"]]
    if summary["probes"]:
        out += ["", "PROBES"] + [f"  {c}  {p}  -> {code}" for c, p, code in summary["probes"][:20]]
    if summary["non_json_samples"]:
        out += ["", "NON-JSON / ERROR SAMPLES"] + [f"  {s[:300]}" for s in summary["non_json_samples"][:10]]
    return "\n".join(out)


# ---------- claude ----------
def claude_report(meta, summary, metrics, flags, history, kept, start, end):
    import anthropic

    body = (
        f"Window: {start.isoformat()} to {end.isoformat()}\n"
        f"Container: {json.dumps(meta)}\n"
        f"Rule flags: {json.dumps(flags)}\n"
        f"Today's metrics: {json.dumps(metrics)}\n"
        f"Baseline (last {len(history)} days): {json.dumps([d['metrics'] for d in history])}\n"
        f"Summary: {json.dumps(summary, default=str)}\n\n"
        "Remaining log lines:\n" + "\n".join(kept)
    )
    resp = anthropic.Anthropic().messages.create(
        model=MODEL, max_tokens=2000, system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": body}],
    )
    return "".join(b.text for b in resp.content if b.type == "text")


# ---------- html email ----------
# Email-safe: tables + inline styles only (Gmail strips <style> in many cases, no JS/CSS files).
SEV_COLOR = {"ATTENTION": ("#b42318", "#fef3f2"), "WARN": ("#b54708", "#fffaeb"), "INFO": ("#475467", "#f2f4f7")}
CLASS_COLOR = {"user": "#2e90fa", "search_crawler": "#12b76a", "ai_crawler": "#7a5af8",
               "monitor": "#0e9384", "bot": "#f79009", "unknown": "#98a2b3"}
CLASS_LABEL = {"user": "Users", "search_crawler": "Search", "ai_crawler": "AI crawlers",
               "monitor": "Monitors", "bot": "Bots", "unknown": "Unknown"}
FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
MONO = "SFMono-Regular,Menlo,Consolas,monospace"


def _e(v):
    return html_lib.escape(str(v))


def _status_colors(status_line):
    s = status_line.upper()
    if s.startswith("ALL CLEAR"):
        return "#067647", "#ecfdf3", "✅"
    if s.startswith("WARN"):
        return "#b54708", "#fffaeb", "⚠️"
    return "#b42318", "#fef3f2", "🚨"


def _card(title, body, accent="#d0d5dd"):
    return (f'<tr><td style="padding:0 0 16px"><table width="100%" cellpadding="0" cellspacing="0" '
            f'style="background:#ffffff;border:1px solid #eaecf0;border-top:3px solid {accent};border-radius:8px">'
            f'<tr><td style="padding:14px 18px 4px;font:600 13px {FONT};color:#344054;letter-spacing:.04em;'
            f'text-transform:uppercase">{_e(title)}</td></tr>'
            f'<tr><td style="padding:4px 18px 16px;font:14px/1.5 {FONT};color:#101828">{body}</td></tr>'
            f'</table></td></tr>')


def _table(headers, rows, mono_cols=(), align_right=()):
    th = "".join(f'<th style="text-align:{"right" if i in align_right else "left"};padding:6px 8px;'
                 f'font:600 12px {FONT};color:#667085;border-bottom:1px solid #eaecf0">{_e(h)}</th>'
                 for i, h in enumerate(headers))
    trs = []
    for r, row in enumerate(rows):
        bg = "#f9fafb" if r % 2 else "#ffffff"
        tds = "".join(
            f'<td style="padding:6px 8px;text-align:{"right" if i in align_right else "left"};'
            f'font:13px {MONO if i in mono_cols else FONT};color:#101828;word-break:break-all">{cell}</td>'
            for i, cell in enumerate(row))
        trs.append(f'<tr style="background:{bg}">{tds}</tr>')
    return f'<table width="100%" cellpadding="0" cellspacing="0"><tr>{th}</tr>{"".join(trs)}</table>'


def _pill(text, fg, bg):
    return (f'<span style="display:inline-block;padding:2px 8px;border-radius:999px;background:{bg};'
            f'color:{fg};font:600 11px {FONT};white-space:nowrap">{_e(text)}</span>')


def _claude_html(text):
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("STATUS:"):
            continue
        if re.match(r"^\d\.\s", s):
            out.append(f'<div style="margin:14px 0 4px;font:600 14px {FONT};color:#344054">{_e(s)}</div>')
        elif s.startswith(("- ", "* ", "• ")):
            out.append(f'<div style="margin:2px 0 2px 14px">• {_e(s[2:])}</div>')
        else:
            out.append(f'<div style="margin:2px 0">{_e(s)}</div>')
    return "".join(out)


def render_html(summary, metrics, flags, meta, start, end, status_line, claude_text, claude_error, coverage_h):
    fg, bg, icon = _status_colors(status_line)
    h, t = summary["health"], summary["traffic_classes"]
    total = sum(v["requests"] for v in t.values()) or 1
    parts = []

    # header banner
    parts.append(
        f'<tr><td style="padding:0 0 16px"><table width="100%" cellpadding="0" cellspacing="0" '
        f'style="background:{bg};border:1px solid {fg}33;border-radius:10px"><tr><td style="padding:18px 20px">'
        f'<div style="font:600 12px {FONT};color:#475467;letter-spacing:.06em;text-transform:uppercase">'
        f'🍺 {_e(APP)} · nightly log report</div>'
        f'<div style="margin-top:6px;font:700 22px {FONT};color:{fg}">{icon} {_e(status_line)}</div>'
        f'<div style="margin-top:6px;font:13px {FONT};color:#475467">{start:%a %b %d %H:%M} → '
        f'{end:%a %b %d %H:%M} ({_e(TZ.key)}) · container <b>{_e(meta["status"])}</b>'
        f'{" · logs cover " + f"{coverage_h:.1f}h" if coverage_h < WINDOW_HOURS else ""}</div>'
        f'</td></tr></table></td></tr>')

    # KPI tiles
    def tile(label, value, color="#101828"):
        return (f'<td width="25%" style="padding:4px"><table width="100%" cellpadding="0" cellspacing="0" '
                f'style="background:#ffffff;border:1px solid #eaecf0;border-radius:8px"><tr><td style="padding:12px 14px">'
                f'<div style="font:12px {FONT};color:#667085">{_e(label)}</div>'
                f'<div style="font:700 22px {FONT};color:{color};margin-top:2px">{_e(value)}</div>'
                f'</td></tr></table></td>')
    p95 = h.get("p95_ms")
    tiles = [
        tile("Requests", metrics["requests"]),
        tile("Real users", f'{metrics["user_ips"]} IP{"s" if metrics["user_ips"] != 1 else ""}', CLASS_COLOR["user"]),
        tile("5xx errors", metrics["errors_5xx"], "#b42318" if metrics["errors_5xx"] else "#067647"),
        tile("Health p95", f"{p95} ms" if p95 is not None else "n/a",
             "#b54708" if p95 and p95 > HEALTH_P95_WARN_MS else "#067647"),
    ]
    parts.append(f'<tr><td style="padding:0 0 12px"><table width="100%" cellpadding="0" cellspacing="0">'
                 f'<tr>{"".join(tiles)}</tr></table></td></tr>')

    # flags
    sev_rank = {"ATTENTION": 0, "WARN": 1, "INFO": 2}
    rows = [[_pill(s, *SEV_COLOR[s]), _e(m)] for s, m in sorted(flags, key=lambda f: sev_rank[f[0]])]
    parts.append(_card("Flags", _table(["", "Finding"], rows) if rows else "None", SEV_COLOR[flags[0][0]][0] if flags else "#12b76a"))

    # Claude analysis
    if claude_text:
        parts.append(_card("Claude analysis", _claude_html(claude_text), "#7a5af8"))
    elif claude_error:
        parts.append(_card("Claude analysis", f'<span style="color:#b42318">Failed: {_e(claude_error)}</span>', "#b42318"))

    # traffic bar + legend
    segs = "".join(
        f'<td width="{max(1, round(100 * v["requests"] / total))}%" style="background:{CLASS_COLOR[c]};height:14px;'
        f'font-size:0;line-height:0">&nbsp;</td>'
        for c, v in t.items() if v["requests"])
    empty = '<td style="background:#eaecf0;height:14px">&nbsp;</td>'
    bar = (f'<table width="100%" cellpadding="0" cellspacing="0" style="border-radius:7px;overflow:hidden">'
           f'<tr>{segs or empty}</tr></table>')
    legend = "".join(
        f'<span style="display:inline-block;margin:8px 14px 0 0;font:13px {FONT};color:#344054">'
        f'<span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:{CLASS_COLOR[c]};'
        f'vertical-align:middle"></span>&nbsp;{CLASS_LABEL[c]} <b>{v["requests"]}</b>'
        f'<span style="color:#98a2b3"> / {v["ips"]} IP</span></span>'
        for c, v in t.items())
    parts.append(_card("Traffic", bar + legend, CLASS_COLOR["user"]))

    # health + status codes
    codes = " ".join(
        _pill(f"{k} × {v}", *(("#067647", "#ecfdf3") if k.startswith(("2", "3")) else
                              ("#b54708", "#fffaeb") if k.startswith("4") else ("#b42318", "#fef3f2")))
        for k, v in sorted(summary["status_codes"].items()))
    gaps = h.get("gaps") or []
    health = (f'<div>{h.get("healthy_checks")} healthy checks · p50 <b>{h.get("p50_ms", "n/a")}</b> · '
              f'p95 <b>{h.get("p95_ms", "n/a")}</b> · max <b>{h.get("max_ms", "n/a")}</b> ms · '
              f'gaps <b style="color:{"#b42318" if gaps else "#067647"}">{len(gaps)}</b></div>'
              f'<div style="margin-top:8px">{codes or "No requests"}</div>'
              f'<div style="margin-top:8px;color:#667085;font-size:12px">Startup/app info lines: '
              f'{summary["benign_startup_lines"]} · own requests ignored: {summary["ignored_own_requests"]} '
              f'(home IP: {_e(", ".join(summary["home_ips"]) or "not detected")})</div>')
    parts.append(_card("Health & status codes", health, "#12b76a"))

    # top paths / clients / user agents
    if summary["top_paths"]:
        parts.append(_card("Top paths", _table(["Hits", "Path"], [[n, _e(p)] for p, n in summary["top_paths"][:10]],
                                               mono_cols=(1,), align_right=(0,))))
    if summary["top_clients"]:
        rows = [[n, _e(c), _pill(CLASS_LABEL.get(summary["client_class"].get(c), "?"),
                                 "#ffffff", CLASS_COLOR.get(summary["client_class"].get(c), "#98a2b3"))]
                for c, n in summary["top_clients"][:10]]
        parts.append(_card("Top clients", _table(["Hits", "IP", "Class"], rows, mono_cols=(1,), align_right=(0,))))
    if summary["top_user_agents"]:
        parts.append(_card("Top user agents", _table(["Hits", "User agent"],
                                                     [[n, _e(u)] for u, n in summary["top_user_agents"][:8]],
                                                     align_right=(0,))))

    # security
    if summary["spoofed_crawlers"]:
        parts.append(_card("Spoofed crawlers", _table(["IP", "Claims", "User agent"],
                                                      [[_e(i), _e(n), _e(u)] for i, n, u in summary["spoofed_crawlers"]],
                                                      mono_cols=(0,)), "#b42318"))
    if summary["probes"]:
        parts.append(_card("Probes", _table(["IP", "Path", "Status"],
                                            [[_e(c), _e(p), _e(s)] for c, p, s in summary["probes"][:20]],
                                            mono_cols=(0, 1)), "#f79009"))
    if summary["slow_requests"]:
        parts.append(_card("Slow requests", _table(["ms", "Path"], [[ms, _e(p)] for p, ms in summary["slow_requests"][:10]],
                                                   mono_cols=(1,), align_right=(0,)), "#f79009"))
    if summary["non_json_samples"]:
        pre = "<br>".join(_e(s[:300]) for s in summary["non_json_samples"][:10])
        parts.append(_card("Non-JSON / error output",
                           f'<div style="font:12px/1.5 {MONO};background:#101828;color:#fda29b;padding:10px 12px;'
                           f'border-radius:6px;word-break:break-all">{pre}</div>', "#b42318"))

    footer = (f'<tr><td style="padding:4px 4px 0;font:12px {FONT};color:#98a2b3">{_e(APP)} · container {_e(CONTAINER)} · '
              f'image {_e(meta["image"])} · started {_e(meta["started_at"])} · '
              f'bot ranges: {_e(BOTS.source if BOTS else "n/a")} · mode {_e(MODE)} · logwatch {_e(VERSION)}</td></tr>')
    return (f'<!doctype html><html><body style="margin:0;padding:0;background:#f2f4f7">'
            f'<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f4f7"><tr><td align="center" '
            f'style="padding:24px 12px"><table width="100%" cellpadding="0" cellspacing="0" style="max-width:680px">'
            f'{"".join(parts)}{footer}</table></td></tr></table></body></html>')


# ---------- delivery ----------
def send(subject, text, html=None):
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, os.environ["SMTP_USER"], os.environ["MAIL_TO"]
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    with smtplib.SMTP(os.getenv("SMTP_HOST", "smtp.gmail.com"), int(os.getenv("SMTP_PORT", "587"))) as s:
        s.starttls()
        s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
        s.send_message(msg)


# ---------- orchestration ----------
def run_once():
    state = load_state()
    end = dt.datetime.now(TZ)
    start = end - dt.timedelta(hours=WINDOW_HOURS)
    if (last := _ts(state.get("last_run"))):  # cover missed nights, no overlap
        start = max(min(last, start), end - dt.timedelta(hours=MAX_CATCHUP_HOURS))

    global BOTS, HOME_IPS
    BOTS = load_bot_db()
    refresh_home_ips(state)
    HOME_IPS = home_ips_for_window(state, start)
    lines, meta = collect(int(start.timestamp()))
    summary, metrics, kept = digest(lines)
    flags = evaluate(summary, metrics, meta, state, len(lines))
    # docker logs only exist since the container was (re)created, e.g. by Watchtower.
    coverage_h = WINDOW_HOURS
    started = _ts((meta.get("started_at") or "")[:26].rstrip("Z") + "+00:00")
    if started and started > start:
        coverage_h = (end - started).total_seconds() / 3600
        flags.append(("INFO", f"Logs cover only {coverage_h:.1f}h: container (re)started "
                              f"{started.astimezone(TZ):%Y-%m-%d %H:%M}"))
        flags.sort(key=lambda f: -SEVERITY_ORDER[f[0]])
    history = state.get("history", [])[-BASELINE_DAYS:]
    w = worst(flags)

    report = rules_report(summary, metrics, flags, meta, start, end)
    claude_text = claude_error = None
    if MODE == "claude" or (MODE == "hybrid" and w > 0):
        try:
            claude_text = claude_report(meta, summary, metrics, flags, history, kept, start, end)
            report = claude_text + "\n\n---- rule engine ----\n" + report
        except Exception as ex:
            claude_error = str(ex)
            report = f"[Claude analysis failed: {ex}; rule report follows]\n\n" + report

    status_line = next(l for l in report.splitlines() if l.startswith("STATUS:")).replace("STATUS:", "").strip()
    if w > 0 or SEND_IF_CLEAR:
        html = render_html(summary, metrics, flags, meta, start, end, status_line,
                           claude_text, claude_error, coverage_h)
        send(f"{APP} log report {end:%Y-%m-%d}: {status_line}", report, html)

    if coverage_h >= 0.8 * WINDOW_HOURS:  # partial days would skew the baseline
        state["history"] = (state.get("history", []) + [{"date": end.date().isoformat(), "metrics": metrics}])[-HISTORY_KEEP:]
    state.update(last_run=end.isoformat(), started_at=meta.get("started_at"))
    save_state(state)
    print(f"{end.isoformat()} app={APP} container={CONTAINER} mode={MODE} {status_line}", flush=True)


def next_run():
    hour, minute = map(int, RUN_AT.split(":"))
    now = dt.datetime.now(TZ)
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return target if target > now else target + dt.timedelta(days=1)


def safe_run():
    try:
        run_once()
    except Exception:
        err = traceback.format_exc()
        print(err, flush=True)
        try:
            send(f"{APP} logwatch FAILED", err)
        except Exception:
            print(traceback.format_exc(), flush=True)


if __name__ == "__main__":
    print(f"logwatch {VERSION}: watching {CONTAINER} as {APP}, mode={MODE}, daily at {RUN_AT}", flush=True)
    if os.getenv("RUN_ON_START") == "1":
        safe_run()
    while True:
        target = next_run()
        print(f"next run {target.isoformat()}", flush=True)
        while (remaining := (target - dt.datetime.now(TZ)).total_seconds()) > 0:
            time.sleep(min(remaining, HOME_IP_CHECK_MIN * 60))
            if AUTO_IGNORE_HOME and dt.datetime.now(TZ) < target:
                try:
                    st = load_state()
                    refresh_home_ips(st)
                    save_state(st)
                except Exception:
                    print(traceback.format_exc(), flush=True)
        safe_run()
