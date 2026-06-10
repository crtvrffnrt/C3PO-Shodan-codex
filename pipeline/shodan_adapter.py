from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_subtaker_module():
    path = Path(__file__).resolve().parent.parent / "subtaker.py"
    spec = importlib.util.spec_from_file_location("subtaker", path)
    if not spec or not spec.loader:
        raise RuntimeError("Unable to load subtaker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _config_bool(config: dict, key: str, default: bool = False) -> bool:
    value = str(config.get(key, str(default))).strip().lower()
    return value in {"1", "true", "yes", "on"}


def discover_shodan_assets(domain: str, provider_fragments: str, config: dict, debug: bool = False) -> dict:
    subtaker = _load_subtaker_module()
    return subtaker.run_domain_shodan_checks(
        domain=domain,
        provider_fragments=provider_fragments,
        dns_page_limit=int(config.get("shodan_dns_page_limit", 12) or 12),
        host_enrichment_limit=int(config.get("shodan_host_enrichment_limit", 100) or 100),
        web_probe_timeout=int(config.get("web_probe_timeout_seconds", 20) or 20),
        max_hosts_for_http_probe=int(config.get("max_hosts_for_http_probe", 250) or 250),
        report_host_limit=int(config.get("report_host_limit", 250) or 250),
        dns_resolve_limit=int(config.get("dns_resolve_limit", 500) or 500),
        subfinder_timeout=int(config.get("subfinder_timeout_seconds", 900) or 900),
        chaos_enabled=_config_bool(config, "chaos_enabled", True),
        chaos_timeout=int(config.get("chaos_timeout_seconds", 900) or 900),
        shodan_search_enabled=_config_bool(config, "shodan_search_enabled", True),
        shodan_search_page_limit=int(config.get("shodan_search_page_limit", 5) or 5),
        nmap_enabled=_config_bool(config, "nmap_enabled", True),
        nmap_target_limit=int(config.get("nmap_target_limit", 100) or 100),
        nmap_top_ports=str(config.get("nmap_top_ports", "1000") or "1000"),
        nmap_timeout=int(config.get("nmap_timeout_seconds", 900) or 900),
        nmap_timing=str(config.get("nmap_timing", "T3") or "T3"),
        nmap_concurrency=int(config.get("nmap_concurrency", 4) or 4),
        debug=debug,
    )
