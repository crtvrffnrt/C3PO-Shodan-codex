#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import subprocess

# Resolve GOPATH (prefer go env, fallback to ~/go)
try:
    gopath = subprocess.check_output(
        ["go", "env", "GOPATH"], text=True
    ).strip()
except Exception:
    gopath = os.path.expanduser("~/go")

os.environ["GOPATH"] = gopath

# GOBIN = GOPATH/bin
gobin = os.path.join(gopath, "bin")
os.environ["GOBIN"] = gobin

# Extend PATH safely
current_path = os.environ.get("PATH", "")

paths_to_add = [
    gobin,
    "/usr/local/go/bin",
    os.path.expanduser("~/go/bin"),
]

for p in paths_to_add:
    if p not in current_path:
        current_path += f":{p}"

os.environ["PATH"] = current_path



def log_err(msg: str, debug: bool) -> None:
    if debug:
        print(msg)
    else:
        print(msg, file=sys.stderr)


def log_dbg(msg: str, debug: bool) -> None:
    if debug:
        print(f"[debug] {msg}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subtaker.py",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "Query Shodan DNS data for target domains and match results against\n"
            "suffix fragments. Emits a live table to stdout and optionally writes\n"
            "JSON/CSV output files."
        ),
        epilog=(
            "Examples:\n"
            "  ./subtaker.py -i scope.txt -d target-domainfragments.txt\n"
            "  ./subtaker.py -i scope.txt -d target-domainfragments.txt -O json --output out.json\n"
        ),
    )
    parser.add_argument("-i", dest="input_file", help="Input scope file (required).")
    parser.add_argument("-d", dest="fragments_file", help="Suffix fragments file (required).")
    parser.add_argument(
        "-O",
        dest="out_format",
        default="table",
        choices=["table", "json", "csv"],
        help="Output file format when --output is used. Default: table.",
    )
    parser.add_argument("--output", dest="out_file", default="", help="Write JSON/CSV to this file.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument(
        "-scope",
        dest="scope",
        choices=["trafficmanager", "storage", "websites", "frontdoor"],
        help="Filter CNAME targets by product (trafficmanager, storage, websites, frontdoor).",
    )
    parser.add_argument("-h", "--help", action="store_true", dest="help_flag", help="Show this help and exit.")
    return parser


def print_help_if_requested(parser: argparse.ArgumentParser, argv) -> None:
    if any(arg in ("-h", "--help") for arg in argv):
        parser.print_help()
        sys.exit(0)


def read_lines(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            yield line


def load_suffixes(path: str):
    suffixes = []
    for line in read_lines(path):
        normalized = "".join(line.split()).lower().rstrip(".")
        if normalized:
            suffixes.append(normalized)
    return suffixes


def normalize_domain(raw: str) -> str:
    if not raw: return ""
    value = raw.strip()
    if "://" in value:
        value = urllib.parse.urlparse(value).netloc or value
    value = value.split("/", 1)[0].strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def core_domain(domain: str) -> str:
    parts = [part for part in domain.split(".") if part]
    if len(parts) <= 2:
        return domain
    sld_tlds = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "co.nz", "com.au", "net.au",
        "org.au", "co.jp", "com.br", "com.mx", "com.tr", "com.cn", "com.hk", "com.sg",
    }
    last_two = ".".join(parts[-2:])
    if last_two in sld_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def is_suffix_match(host: str, suffixes) -> bool:
    if not host:
        return False
    host = host.rstrip(".").lower()
    for suffix in suffixes:
        if host == suffix or host.endswith(f".{suffix}"):
            return True
    return False


def redact_url(url: str) -> str:
    if "key=" not in url:
        return url
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    redacted = [(k, "REDACTED" if k == "key" else v) for k, v in query]
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(redacted), parts.fragment)
    )


def shodan_api_info(api_key: str, debug: bool) -> tuple[str, int]:
    url = f"https://api.shodan.io/api-info?key={api_key}"
    body, status, _ = shodan_get(url, debug)
    return body, status


def shodan_get(url: str, debug: bool, passthrough: any = None) -> tuple[str, int, any]:
    attempt = 0
    max_attempts = 5
    delay = 1
    while attempt < max_attempts:
        attempt += 1
        log_dbg(f"Shodan request (attempt {attempt}/{max_attempts}): {redact_url(url)}", debug)
        try:
            with urllib.request.urlopen(url, timeout=20) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                status = resp.getcode()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            log_dbg(f"Request failed: {redact_url(url)}", debug)
            return ("", 0, passthrough)

        if status == 200:
            log_dbg(f"Shodan response 200 for: {redact_url(url)}", debug)
            return (body, status, passthrough)

        if status == 429 or "rate limit" in body.lower():
            log_dbg(f"Rate limited (status {status}); backing off {delay}s", debug)
            time.sleep(delay)
            delay *= 2
            continue

        log_dbg(f"Shodan API error ({status}): {redact_url(url)}", debug)
        return ("", status, passthrough)

    log_dbg(f"Shodan API rate limit exceeded: {redact_url(url)}", debug)
    return ("", 429, passthrough)


def load_shodan_key_file() -> str:
    path = os.path.expanduser("~/.shodan/api_key")
    if not os.path.isfile(path):
        return ""
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


FRONTDOOR_SUFFIXES = ("azurefd.net",)
SCOPE_SUFFIXES = {
    "trafficmanager": ("trafficmanager.net",),
    "storage": ("core.windows.net",),
    "websites": ("azurewebsites.net",),
    "frontdoor": FRONTDOOR_SUFFIXES,
}
def resolve_httpx_binary() -> str:
    candidates = []
    env_path = os.environ.get("HTTPX_BIN", "").strip()
    if env_path:
        candidates.append(env_path)

    home = Path.home()
    candidates.extend(
        [
            str(home / ".pdtm" / "go" / "bin" / "httpx"),
            str(home / "go" / "bin" / "httpx"),
            shutil.which("httpx") or "",
            "/usr/local/bin/httpx",
            "/usr/bin/httpx",
        ]
    )

    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except Exception:
        return False


def network_hint_for_ip(value: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(str(value))
        prefix = 64 if ip_obj.version == 6 else 24
        return str(ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False))
    except Exception:
        return ""


def dedupe_preserve(items) -> list:
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def resolve_hostname_ips(hostname: str, debug: bool = False) -> tuple[str, list[str]]:
    ips = set()
    try:
        for result in socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP):
            address = result[4][0]
            if is_ip_address(address):
                ips.add(address)
    except Exception as exc:
        log_dbg(f"DNS resolution failed for {hostname}: {exc}", debug)
    return hostname, sorted(ips, key=lambda item: (":" in item, item))


HTTPX_STATE = {
    "path": resolve_httpx_binary(),
    "disabled_reason": "",
}


def extract_hostname(raw: str) -> str:
    host = raw.strip().lower()
    if not host:
        return ""
    if "://" in host:
        host = urllib.parse.urlparse(host).netloc or host
    host = host.split("/", 1)[0]
    host = host.split("#", 1)[0]
    host = host.split("?", 1)[0]
    return host.strip().rstrip(".")


def print_header() -> None:
    print(f"{'DOMAIN':<30} {'SUBDOMAIN':<45} VALUE")
    print(f"{'------':<30} {'---------':<45} -----")


def init_output_writer(args):
    if not args.out_file or args.out_format not in ("json", "csv"):
        return (None, None)
    if args.out_format == "csv":
        handle = open(args.out_file, "w", encoding="utf-8", newline="")
        writer = csv.writer(handle)
        writer.writerow(["domain", "subdomain", "value"])
        handle.flush()

        def emit(item):
            writer.writerow([item["domain"], item["subdomain"], item["value"]])
            handle.flush()

        return (handle, emit)

    handle = open(args.out_file, "w", encoding="utf-8")
    close_str = "\n]\n"
    handle.write("[\n]\n")
    handle.flush()
    state = {"first": True, "pos": len("[\n")}

    def emit(item):
        payload = json.dumps(item, separators=(",", ":"))
        handle.seek(state["pos"])
        prefix = "" if state["first"] else ",\n"
        handle.write(f"{prefix}{payload}")
        handle.write(close_str)
        handle.flush()
        state["pos"] = handle.tell() - len(close_str)
        state["first"] = False

    return (handle, emit)


def probe_http_simple(hostname: str, timeout: int = 20) -> dict:
    """Simple HTTP/S probe using urllib."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "C3PO-shodan/1.0"})
            with urllib.request.urlopen(req, timeout=max(1, timeout), context=ctx) as resp:
                status = resp.getcode()
                content = resp.read(16384).decode("utf-8", errors="replace")
                title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip() if title_match else ""
                return {
                    "probed": True, "reachable": True, "scheme": scheme, "url": url,
                    "status_code": status, "title": title[:100]
                }
        except Exception:
            continue
    return {"probed": True, "reachable": False, "scheme": "", "url": "", "status_code": 0, "title": ""}


def choose_httpx_target(hostname: str, http_info: dict, ports: list[int] | set[int] | tuple[int, ...]) -> str:
    url = str(http_info.get("url") or "").strip()
    if url:
        return url

    try:
        port_set = {int(port) for port in ports}
    except Exception:
        port_set = set()

    if 443 in port_set or 8443 in port_set:
        return f"https://{hostname}"
    if 80 in port_set or 8080 in port_set:
        return f"http://{hostname}"
    return ""


def probe_httpx_stack(target: str, debug: bool, timeout: int = 15) -> dict:
    result = {
        "checked": False,
        "status": "skipped",
        "source": "httpx",
        "target": target,
        "reason": "",
        "result": {},
    }

    if not target:
        result["reason"] = "No web endpoint available for httpx enrichment."
        return result

    httpx_path = HTTPX_STATE.get("path")
    if not httpx_path:
        result["reason"] = "httpx is not installed."
        return result

    if HTTPX_STATE.get("disabled_reason"):
        result["reason"] = HTTPX_STATE["disabled_reason"]
        return result

    cmd = [
        httpx_path,
        "-td",
        "-json",
        "-title",
        "-status-code",
        "-web-server",
        "-ip",
        "-cdn",
        "-asn",
        "-timeout",
        str(timeout),
        "-retries",
        "1",
        "-silent",
    ]
    log_dbg(f"Running httpx enrichment for {target}", debug)
    try:
        completed = subprocess.run(
            cmd,
            input=f"{target}\n",
            capture_output=True,
            text=True,
            timeout=timeout + 10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        result["status"] = "error"
        result["reason"] = f"httpx timed out after {timeout + 10}s."
        return result
    except Exception as exc:
        HTTPX_STATE["disabled_reason"] = f"httpx execution failed: {exc}"
        result["reason"] = HTTPX_STATE["disabled_reason"]
        return result

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        HTTPX_STATE["disabled_reason"] = stderr or f"httpx exited with status {completed.returncode}."
        result["reason"] = HTTPX_STATE["disabled_reason"]
        return result

    payload = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            break
        except json.JSONDecodeError:
            continue

    if not payload:
        result["status"] = "error"
        result["reason"] = stderr or "httpx returned no JSON result."
        return result

    result["checked"] = True
    result["status"] = "ok"
    result["reason"] = ""
    result["result"] = payload
    return result


def fetch_subdomains_subfinder(domain: str, debug: bool = False, timeout: int = 900) -> list[str]:
    """Fetch hostnames using subfinder."""
    log_dbg(f"Running subfinder for {domain}...", debug)
    hosts = set()
    if not shutil.which("subfinder"):
        log_dbg("subfinder is not installed; skipping subfinder discovery.", debug)
        return []
    try:
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=max(30, timeout))
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                host = normalize_domain(line.strip())
                if host and host.endswith(domain) and "*" not in host:
                    hosts.add(host)
            if hosts:
                log_dbg(f"Found {len(hosts)} unique hosts using subfinder", debug)
    except subprocess.TimeoutExpired:
        log_dbg(f"subfinder timed out after {timeout}s", debug)
    except Exception as e:
        log_dbg(f"subfinder error: {e}", debug)
    return sorted(list(hosts))


def fetch_subdomains_chaos(domain: str, debug: bool = False, timeout: int = 900) -> list[str]:
    """Fetch hostnames using ProjectDiscovery chaos-client when configured locally."""
    log_dbg(f"Running chaos-client for {domain}...", debug)
    hosts = set()
    if not shutil.which("chaos-client"):
        log_dbg("chaos-client is not installed; skipping chaos discovery.", debug)
        return []

    commands = [
        ["chaos-client", "-d", domain, "-silent"],
        ["chaos-client", "-d", domain],
    ]
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=max(30, timeout))
        except subprocess.TimeoutExpired:
            log_dbg(f"{' '.join(cmd)} timed out after {timeout}s", debug)
            continue
        except Exception as exc:
            log_dbg(f"chaos-client error: {exc}", debug)
            continue
        if result.returncode != 0 and not result.stdout.strip():
            log_dbg(f"chaos-client returned {result.returncode}: {(result.stderr or '').strip()}", debug)
            continue
        for line in result.stdout.splitlines():
            host = normalize_domain(line.strip())
            if host and host.endswith(domain) and "*" not in host:
                hosts.add(host)
        break

    if hosts:
        log_dbg(f"Found {len(hosts)} unique hosts using chaos-client", debug)
    return sorted(hosts)


def fetch_shodan_hostname_search(domain: str, api_key: str, page_limit: int, debug: bool = False) -> tuple[list[dict], dict[str, set[str]]]:
    """Search Shodan for hostname:*.domain and return DNS-like records plus source hints."""
    records = []
    source_hosts: dict[str, set[str]] = defaultdict(set)
    seen_records = set()
    query = urllib.parse.quote(f"hostname:*.{domain}")
    for page in range(1, max(page_limit, 0) + 1):
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}&page={page}"
        body, status, _ = shodan_get(url, debug)
        if status != 200 or not body:
            continue
        try:
            payload = json.loads(body)
        except Exception:
            continue
        matches = payload.get("matches", []) or []
        if not matches and page > 1:
            break
        for match in matches:
            ip = str(match.get("ip_str") or "").strip()
            host_candidates = set()
            for value in match.get("hostnames", []) or []:
                host = normalize_domain(value)
                if host and host.endswith(domain) and "*" not in host:
                    host_candidates.add(host)
            for value in match.get("domains", []) or []:
                host = normalize_domain(value)
                if host and host.endswith(domain) and "*" not in host:
                    host_candidates.add(host)
            ssl_names = match.get("ssl", {}).get("cert", {}).get("subject", {})
            cn = normalize_domain(ssl_names.get("CN", "") if isinstance(ssl_names, dict) else "")
            if cn and cn.endswith(domain) and "*" not in cn:
                host_candidates.add(cn)

            for host in host_candidates:
                source_hosts[host].add("shodan_search")
                if ip and is_ip_address(ip):
                    key = (host, "AAAA" if ":" in ip else "A", ip, "shodan_search")
                    if key not in seen_records:
                        seen_records.add(key)
                        records.append({
                            "hostname": host,
                            "type": "AAAA" if ":" in ip else "A",
                            "value": ip,
                            "last_seen": str(match.get("timestamp") or ""),
                            "source": "shodan_search",
                        })
        if len(matches) < 100:
            break
    return records, source_hosts


def scan_nmap_ports(ip: str, top_ports: str, timing: str, timeout: int, debug: bool = False) -> dict:
    result = {"ip": ip, "ports": [], "products": [], "services": {}, "status": "skipped", "reason": ""}
    if not shutil.which("nmap"):
        result["reason"] = "nmap is not installed."
        return result
    cmd = ["nmap", "-Pn", f"-{timing}", "--top-ports", str(top_ports), "-oX", "-", ip]
    log_dbg(f"Running nmap port discovery for {ip}", debug)
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=max(30, timeout))
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["reason"] = f"nmap timed out after {timeout}s."
        return result
    except Exception as exc:
        result["status"] = "error"
        result["reason"] = str(exc)
        return result

    if completed.returncode not in (0, 1) or not completed.stdout.strip():
        result["status"] = "error"
        result["reason"] = (completed.stderr or f"nmap exited with status {completed.returncode}").strip()
        return result

    try:
        root = ET.fromstring(completed.stdout)
    except Exception as exc:
        result["status"] = "error"
        result["reason"] = f"Unable to parse nmap XML: {exc}"
        return result

    ports = set()
    products = set()
    services = {}
    for port_node in root.findall(".//port"):
        state_node = port_node.find("state")
        if state_node is None or state_node.get("state") != "open":
            continue
        try:
            port_id = int(port_node.get("portid", "0"))
        except Exception:
            continue
        if not port_id:
            continue
        ports.add(port_id)
        service_node = port_node.find("service")
        if service_node is not None:
            service_name = service_node.get("name", "")
            product = " ".join(
                item for item in [
                    service_node.get("product", ""),
                    service_node.get("version", ""),
                ]
                if item
            ).strip()
            if product:
                products.add(product)
            services[str(port_id)] = {
                "name": service_name,
                "product": product,
            }

    result.update({
        "ports": sorted(ports),
        "products": sorted(products)[:20],
        "services": services,
        "status": "ok",
        "reason": "",
    })
    return result


def run_domain_shodan_checks(
    domain: str,
    provider_fragments: str,
    dns_page_limit: int = 12,
    host_enrichment_limit: int = 100,
    web_probe_timeout: int = 20,
    max_hosts_for_http_probe: int = 250,
    report_host_limit: int = 250,
    dns_resolve_limit: int = 500,
    subfinder_timeout: int = 900,
    chaos_enabled: bool = True,
    chaos_timeout: int = 900,
    shodan_search_enabled: bool = True,
    shodan_search_page_limit: int = 5,
    nmap_enabled: bool = True,
    nmap_target_limit: int = 100,
    nmap_top_ports: str = "1000",
    nmap_timeout: int = 900,
    nmap_timing: str = "T3",
    nmap_concurrency: int = 4,
    debug: bool = False,
) -> dict:
    target_domain = core_domain(normalize_domain(domain))
    log_dbg(f"Starting collection for {target_domain}", debug)

    env_key = os.environ.get("SHODANAPI", "").strip()
    file_key = load_shodan_key_file()
    api_key = env_key or file_key
    if not api_key:
        raise RuntimeError("No Shodan API key found")

    info_body, status = shodan_api_info(api_key, debug)
    shodan_info = json.loads(info_body) if status == 200 else {}

    hostname_sources = defaultdict(set)
    hostname_sources[target_domain].add("target")

    log_dbg(f"Discovering subdomains for {target_domain} with subfinder...", debug)
    extra_hosts = fetch_subdomains_subfinder(target_domain, debug=debug, timeout=subfinder_timeout)
    for host in extra_hosts:
        hostname_sources[host].add("subfinder")
    if chaos_enabled:
        log_dbg(f"Discovering subdomains for {target_domain} with chaos-client...", debug)
        for host in fetch_subdomains_chaos(target_domain, debug=debug, timeout=chaos_timeout):
            hostname_sources[host].add("chaos")

    dns_records = []
    dns_record_keys = set()

    def add_dns_record(hostname: str, rec_type: str, value: str, source: str, last_seen: str = "") -> None:
        hostname = normalize_domain(hostname)
        value = str(value or "").strip().rstrip(".")
        if not hostname or not value:
            return
        key = (hostname, rec_type, value, source)
        if key in dns_record_keys:
            return
        dns_record_keys.add(key)
        dns_records.append({
            "hostname": hostname,
            "type": rec_type,
            "value": value,
            "last_seen": str(last_seen or ""),
            "source": source,
        })

    dns_tasks = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        for mode_label, history_flag in [("current", "false"), ("history", "true")]:
            for page in range(1, dns_page_limit + 1):
                url = f"https://api.shodan.io/dns/domain/{target_domain}?key={api_key}&history={history_flag}&page={page}"
                dns_tasks.append(executor.submit(shodan_get, url, debug, (mode_label, page)))

        for future in as_completed(dns_tasks):
            body, status, (mode_label, page) = future.result()
            if status != 200 or not body: continue
            try:
                data = json.loads(body)
            except: continue
            records = data.get("data", [])
            if not records and page > 1: continue
            for entry in records:
                sub = entry.get("subdomain") or ""
                fqdn = f"{sub}.{target_domain}" if sub else target_domain
                fqdn = fqdn.lower().rstrip(".")
                rec_type = entry.get("type", "UNKNOWN")
                value = str(entry.get("value") or "").rstrip(".")
                add_dns_record(fqdn, rec_type, value, f"shodan_dns_{mode_label}", str(entry.get("last_seen") or ""))
                hostname_sources[fqdn].add(f"shodan_dns_{mode_label}")
                val_norm = normalize_domain(value)
                if val_norm.endswith(target_domain):
                    hostname_sources[val_norm].add(f"shodan_dns_{mode_label}")
            for sub in data.get("subdomains", []):
                fqdn = f"{sub}.{target_domain}".lower().rstrip(".")
                hostname_sources[fqdn].add(f"shodan_dns_{mode_label}")

    if shodan_search_enabled:
        log_dbg(f"Searching Shodan for hostname:*.{target_domain}...", debug)
        search_records, search_sources = fetch_shodan_hostname_search(
            target_domain,
            api_key,
            shodan_search_page_limit,
            debug=debug,
        )
        for rec in search_records:
            add_dns_record(rec["hostname"], rec["type"], rec["value"], rec["source"], rec.get("last_seen", ""))
        for host, sources in search_sources.items():
            hostname_sources[host].update(sources)

    resolve_targets = sorted(hostname_sources.keys())[:max(dns_resolve_limit, 0)]
    if resolve_targets:
        log_dbg(f"Resolving {len(resolve_targets)} hostnames via local DNS...", debug)
    with ThreadPoolExecutor(max_workers=24) as executor:
        resolve_tasks = [executor.submit(resolve_hostname_ips, host, debug) for host in resolve_targets]
        for future in as_completed(resolve_tasks):
            host, ips = future.result()
            for ip in ips:
                rec_type = "AAAA" if ":" in ip else "A"
                add_dns_record(host, rec_type, ip, "local_dns")
                hostname_sources[host].add("local_dns")

    unique_ips = set()
    for rec in dns_records:
        if rec["type"] in ("A", "AAAA") and is_ip_address(rec["value"]):
            unique_ips.add(rec["value"])
    
    enrichment_targets = sorted(list(unique_ips))[:host_enrichment_limit]
    ip_assets = []
    ip_summaries = {}
    with ThreadPoolExecutor(max_workers=8) as executor:
        host_tasks = []
        for ip in enrichment_targets:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}&minify=false"
            host_tasks.append(executor.submit(shodan_get, url, debug, ip))
        for future in as_completed(host_tasks):
            body, status, ip = future.result()
            if status == 200 and body:
                data = json.loads(body)
                ports = sorted(data.get("ports", []))
                
                # Extract detailed vulnerability information
                vulns_list = data.get("vulns", [])
                vuln_details = {}
                
                # Check data entries for vulnerability details (summary, cvss)
                for entry in data.get("data", []):
                    entry_vulns = entry.get("vulns", {})
                    if isinstance(entry_vulns, dict):
                        for cve_id, info in entry_vulns.items():
                            if cve_id not in vuln_details:
                                vuln_details[cve_id] = {
                                    "summary": info.get("summary", ""),
                                    "cvss": info.get("cvss", info.get("cvss_v3", info.get("cvss_v2", 0.0))),
                                    "verified": info.get("verified", False)
                                }
                
                # Ensure all CVEs in 'vulns' list have at least a placeholder entry in details
                for cve_id in vulns_list:
                    if cve_id not in vuln_details:
                        vuln_details[cve_id] = {"summary": "No details available.", "cvss": 0.0, "verified": False}

                # Capture HTTP titles and status from Shodan if present
                shodan_http_info = {}
                for entry in data.get("data", []):
                    if "http" in entry:
                        shodan_http_info[entry.get("port", 80)] = {
                            "status": entry["http"].get("status"),
                            "title": entry["http"].get("title"),
                        }

                ip_obj = {
                    "ip": ip, "ports": ports,
                    "products": sorted({entry.get("product") for entry in data.get("data", []) if entry.get("product")})[:10],
                    "vulns": sorted(list(vuln_details.keys())),
                    "vuln_details": vuln_details,
                    "org": data.get("org", ""), "isp": data.get("isp", ""),
                    "asn": data.get("asn", ""), "country": data.get("country_name", ""),
                    "city": data.get("city", "n/a"),
                    "domains": data.get("domains", []),
                    "hostnames": data.get("hostnames", []),
                    "os": data.get("os", ""),
                    "network_hint": network_hint_for_ip(ip),
                    "shodan_http": shodan_http_info,
                    "port_sources": {"shodan": ports} if ports else {},
                }
                ip_assets.append(ip_obj)
                ip_summaries[ip] = ip_obj
                # Add all hostnames from Shodan to our tracking
                for h in data.get("hostnames", []):
                    h_norm = normalize_domain(h)
                    if h_norm.endswith(target_domain):
                        hostname_sources[h_norm].add("shodan_host")
                # Also add domains if relevant
                for d in data.get("domains", []):
                    d_norm = normalize_domain(d)
                    if d_norm.endswith(target_domain):
                        hostname_sources[d_norm].add("shodan_host")

    nmap_results = {}
    if nmap_enabled:
        nmap_targets = sorted(list(unique_ips))[:max(nmap_target_limit, 0)]
        if nmap_targets:
            log_dbg(f"Running nmap on {len(nmap_targets)} IPs...", debug)
        with ThreadPoolExecutor(max_workers=max(1, nmap_concurrency)) as executor:
            nmap_tasks = {
                executor.submit(scan_nmap_ports, ip, nmap_top_ports, nmap_timing, nmap_timeout, debug): ip
                for ip in nmap_targets
            }
            for future in as_completed(nmap_tasks):
                ip = nmap_tasks[future]
                nmap_results[ip] = future.result()

        for ip, scan in nmap_results.items():
            if scan.get("status") != "ok":
                continue
            if ip not in ip_summaries:
                ip_summaries[ip] = {
                    "ip": ip,
                    "ports": [],
                    "products": [],
                    "vulns": [],
                    "vuln_details": {},
                    "org": "",
                    "isp": "",
                    "asn": "",
                    "country": "",
                    "city": "n/a",
                    "domains": [],
                    "hostnames": [],
                    "os": "",
                    "network_hint": network_hint_for_ip(ip),
                    "shodan_http": {},
                }
            summary = ip_summaries[ip]
            summary["ports"] = sorted(set(summary.get("ports", [])) | set(scan.get("ports", [])))
            summary["products"] = sorted(set(summary.get("products", [])) | set(scan.get("products", [])))[:20]
            summary.setdefault("port_sources", {})
            if scan.get("ports"):
                summary["port_sources"]["nmap"] = scan.get("ports", [])
            summary["nmap_services"] = scan.get("services", {})

        ip_assets = sorted(ip_summaries.values(), key=lambda item: item.get("ip", ""))

    fragments = []
    if os.path.isfile(provider_fragments):
        with open(provider_fragments, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip().lower().rstrip(".")
                if line: fragments.append(line)

    all_hostnames = sorted(hostname_sources.keys())
    http_results = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        probe_tasks = {
            executor.submit(probe_http_simple, h, web_probe_timeout): h
            for h in all_hostnames[:max(max_hosts_for_http_probe, 0)]
        }
        for future in as_completed(probe_tasks):
            h = probe_tasks[future]
            http_results[h] = future.result()

    host_profiles = []
    for host in all_hostnames:
        recs = [r for r in dns_records if r["hostname"] == host]
        current_ips = dedupe_preserve([r["value"] for r in recs if r["type"] in ("A", "AAAA") and is_ip_address(r["value"])])
        cnames = dedupe_preserve([r["value"] for r in recs if r["type"] == "CNAME"])
        matches = []
        for cname in cnames:
            cname_norm = normalize_domain(cname)
            for frag in fragments:
                if cname_norm == frag or cname_norm.endswith(f".{frag}"):
                    matches.append({"target": cname_norm, "fragment": frag, "category": "Provider-linked"})
        http_info = http_results.get(host, {"probed": False, "reachable": False, "scheme": "", "url": "", "status_code": 0, "title": ""})
        
        # Fallback to Shodan HTTP info if active probe failed but Shodan has it
        if not http_info["reachable"]:
            for ip in current_ips:
                if ip in ip_summaries:
                    sh_http = ip_summaries[ip].get("shodan_http", {})
                    if sh_http:
                        # Pick first available web port (443, 80, etc)
                        for port in (443, 80, 8080, 8443):
                            if port in sh_http:
                                scheme = "https" if port in (443, 8443) else "http"
                                http_info = {
                                    "probed": True,
                                    "reachable": True,
                                    "scheme": scheme,
                                    "url": f"{scheme}://{host}",
                                    "status_code": sh_http[port].get("status", 200),
                                    "title": f"(Shodan) {sh_http[port].get('title', '')}"[:100]
                                }
                                break
                    if http_info["reachable"]: break
        score = 0
        factors = []
        host_vulns = set()
        host_vuln_details = {}
        host_ports = set()
        for ip in current_ips:
            if ip in ip_summaries:
                summ = ip_summaries[ip]
                if summ["ports"]:
                    score += min(15, len(summ["ports"]) * 2)
                    factors.append(f"Open ports on {ip}: {summ['ports']}")
                    host_ports.update(summ["ports"])
                if summ["vulns"]:
                    score += 25
                    factors.append(f"Vulnerabilities found on {ip}")
                    host_vulns.update(summ["vulns"])
                    host_vuln_details.update(summ.get("vuln_details", {}))
        if http_info["reachable"]:
            score += 15
            factors.append(f"Web service reachable ({http_info['status_code']})")
            if http_info["status_code"] == 200: score += 5
        if matches:
            score += 15
            factors.append(f"Provider-linked CNAME: {', '.join(m['target'] for m in matches)}")
            if not current_ips:
                score += 25
                factors.append("Dangling CNAME (Potential Takeover)")
        level = "low"
        if score >= 70: level = "critical"
        elif score >= 45: level = "high"
        elif score >= 25: level = "medium"
        
        # Aggregate Shodan metadata
        all_cities = set()
        all_domains = set()
        all_hostnames_from_shodan = set()
        for ip in current_ips:
            if ip in ip_summaries:
                s = ip_summaries[ip]
                if s.get("city") and s.get("city") != "n/a": all_cities.add(s["city"])
                all_domains.update(s.get("domains", []))
                all_hostnames_from_shodan.update(s.get("hostnames", []))

        httpx_target = choose_httpx_target(host, http_info, host_ports)
        web_intel = probe_httpx_stack(httpx_target, debug=debug, timeout=web_probe_timeout)

        host_profiles.append({
            "hostname": host, "risk_score": score, "risk_level": level, "risk_factors": factors,
            "vulns": sorted(list(host_vulns)), "vuln_details": host_vuln_details,
            "ports": sorted(list(host_ports)),
            "current_ips": current_ips, "provider_matches": matches,
            "sources": sorted(list(hostname_sources[host])), "http": http_info,
            "web_intel": web_intel,
            "city": ", ".join(sorted(list(all_cities))) or "n/a",
            "shodan_domains": sorted(list(all_domains)),
            "shodan_hostnames": sorted(list(all_hostnames_from_shodan))
        })

    host_profiles.sort(key=lambda x: x["risk_score"], reverse=True)
    all_hosts = host_profiles
    top_hosts = all_hosts[:max(report_host_limit, 0)]

    return {
        "target": {
            "input": domain, "core_domain": target_domain, "slug": target_domain.replace(".", "-"),
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "summary": {
            "host_count": len(top_hosts),
            "web_host_count": sum(1 for h in top_hosts if h["http"]["reachable"]),
            "ip_count": len(ip_assets),
            "critical_count": sum(1 for h in top_hosts if h["risk_level"] == "critical"),
            "high_count": sum(1 for h in top_hosts if h["risk_level"] == "high"),
            "medium_count": sum(1 for h in top_hosts if h["risk_level"] == "medium"),
            "low_count": sum(1 for h in top_hosts if h["risk_level"] == "low"),
            "original_total_hosts": len(all_hosts)
        },
        "discoveries": {
            "dns_records": dns_records,
            "takeover_candidates": [h for h in all_hosts if h["provider_matches"] and not h["current_ips"]]
        },
        "hosts": top_hosts, "ips": ip_assets
    }


def main(argv) -> int:
    parser = build_parser()
    print_help_if_requested(parser, argv)
    args = parser.parse_args(argv)
    if not args.input_file or not args.fragments_file:
        log_err("Missing required input files.", args.debug)
        parser.print_help()
        return 1
    api_key = os.environ.get("SHODANAPI", "").strip() or load_shodan_key_file()
    if not api_key:
        log_err("No Shodan API key found.", args.debug)
        return 1
    suffixes = load_suffixes(args.fragments_file)
    scope_suffixes = SCOPE_SUFFIXES.get(args.scope) if args.scope else ()
    dedupe = set()
    print_header()
    out_handle, emit_output = init_output_writer(args)
    queried = set()
    try:
        for domain in read_lines(args.input_file):
            domain = normalize_domain(domain)
            if not domain: continue
            core = core_domain(domain)
            if core in queried: continue
            queried.add(core)
            url = f"https://api.shodan.io/dns/domain/{core}?key={api_key}&type=CNAME&page=1&history=false"
            body, status, _ = shodan_get(url, args.debug)
            if not body or status != 200: continue
            try:
                data = json.loads(body)
            except: continue
            records = data.get("data", [])
            for entry in records:
                if entry.get("type") != "CNAME": continue
                sub = entry.get("subdomain") or ""
                value = entry.get("value") or ""
                fqdn = f"{sub}.{core}" if sub else core
                if scope_suffixes:
                    if not is_suffix_match(extract_hostname(value), scope_suffixes): continue
                if not is_suffix_match(value, suffixes): continue
                key = f"{core}|{fqdn}|{value}"
                if key in dedupe: continue
                dedupe.add(key)
                item = {"domain": core, "subdomain": fqdn, "value": value}
                if emit_output: emit_output(item)
                print(f"{core:<30} {fqdn:<45} {value}")
    finally:
        if out_handle: out_handle.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
