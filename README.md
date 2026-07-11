<div align="center">
  <img src="logo.jpg" alt="C3PO-shodan logo" width="360">

  <h1>C3PO-shodan</h1>

  <p><strong>A Shodan-driven EASM pipeline for mapping exposed infrastructure, enriching risky web targets, and rendering operator-friendly reports.</strong></p>

  <p>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"></a>
    <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/shell-bash-121011?style=flat-square&logo=gnu-bash&logoColor=white" alt="Bash"></a>
    <a href="https://www.shodan.io/"><img src="https://img.shields.io/badge/data-Shodan-EA4335?style=flat-square" alt="Shodan"></a>
    <a href="https://github.com/projectdiscovery/nuclei"><img src="https://img.shields.io/badge/scanner-Nuclei-0F766E?style=flat-square" alt="Nuclei"></a>
    <a href="https://github.com/projectdiscovery/httpx"><img src="https://img.shields.io/badge/enrichment-httpx-2563EB?style=flat-square" alt="httpx"></a>
    <a href="https://developers.openai.com/codex/"><img src="https://img.shields.io/badge/workflow-OpenAI_Codex-111827?style=flat-square" alt="OpenAI Codex"></a>
  </p>

  <p>
    <a href="#quick-start"><strong>Quick Start</strong></a> •
    <a href="#pipeline"><strong>Pipeline</strong></a> •
    <a href="#configuration"><strong>Configuration</strong></a> •
    <a href="#outputs"><strong>Outputs</strong></a>
  </p>
</div>

---

## Report Preview

The HTML report is designed as a high-contrast attack-surface console with infrastructure summaries, risk scoring, screenshots, and findings in one place.

<div align="center">
  <img src="example.png" alt="Example report view" width="1000">
</div>

## Overview

`C3PO-shodan` is an External Attack Surface Management (EASM) framework with **Codex-oriented operator guidance** and deterministic **bash/Python execution** for discovering and mapping exposed infrastructure. It takes a target root domain, fetches DNS/host metadata using Shodan, detects potential subdomain takeovers, performs targeted Nuclei vulnerability scans, captures web screenshots, and renders interactive reports.

The execution logic is structured to enable LLM-based security agents and human operators to safely direct, validate, and execute complex reconnaissance pipelines.

## What It Does

| Capability | Details |
| --- | --- |
| Discovery | Collects Shodan DNS records, Shodan hostname search hits, subfinder and chaos-client hostnames when available, local DNS resolution, hostname/IP enrichment, and historical Shodan DNS expansion. |
| Risk Signal Collection | Extracts TXT verification signals, provider-linked CNAME patterns, and takeover-oriented indicators. |
| Web Enrichment | Probes reachable HTTP/S targets and adds tech-stack enrichment with `httpx` when available. |
| Vulnerability Triage | Runs Nuclei against prioritized web URLs and bounded protocol targets derived from Shodan and nmap open-port evidence. |
| Visual Evidence | Captures screenshots for up to 50 reachable targets by default, preferring Cloudflare URL Scanner and falling back to local tooling. |
| Reporting | Renders a versioned Markdown report, self-contained HTML dashboard, and supporting JSON artifacts. |

## Quick Start

### 1. Install dependencies

Required:

- `python3` 3.10+
- `bash`
- `curl`
- `nuclei`
- `httpx`

Optional but useful:

- One local screenshot tool: `chromium`, `google-chrome`, `microsoft-edge`, or `wkhtmltoimage`
- `subfinder`, `chaos-client`, and `nmap` for deeper host and port discovery
- Cloudflare API credentials for better screenshots and URL intelligence

Recommended installs:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
nuclei -update-templates
```

Install `chaos-client` according to your ProjectDiscovery setup and ensure the `chaos-client` binary is in `PATH` if you want Chaos discovery.

### 2. Configure credentials

Copy the example env file and add your keys:

```bash
cp .env.example .env
```

Minimum required:

```bash
SHODANAPI=your_shodan_api_key
```

Optional Cloudflare token flow:

```bash
CF_ACCOUNT_ID=your_account_id
CF_API_TOKEN=your_api_token
```

Alternative Shodan key file:

```bash
mkdir -p ~/.shodan
printf '%s\n' "your_shodan_api_key" > ~/.shodan/api_key
chmod 600 ~/.shodan/api_key
```

### 3. Run the pipeline

```bash
chmod +x run.sh bin/run.sh scripts/*.sh install.sh
./install.sh
./run.sh example.com
```

Interactive terminal runs show a Codex operator model menu to choose the lastest model before scanning unless a model is supplied by flag or environment variable. The scanner itself does not invoke Codex; the menu only records operator context for agent-driven workflows.
Recommondation: Use fast models with medium effort depending on the expected size of the attack surface. 
Non-interactive and scripted examples:

```bash
./run.sh example.com --no-model-prompt
./run.sh example.com --model gpt-5.5 --effort low --fast
./run.sh --domain example.com --model gpt-5.4-mini --effort high --no-fast
```

## Pipeline & Execution Flow

The tool operates through **native bash commands and Python helper scripts**. Codex CLI / OpenAI Codex is the intended agentic command-line workflow layer for maintaining and directing this repository, but the scanner itself does not require a Codex subprocess at runtime.

The execution runs through the following sequence of phases:

### Phase 1: Preflight & Validation
- **Commands**: [install.sh](file:///tmp/C3PO-Shodan-codex/install.sh) and [scripts/validate.sh](file:///tmp/C3PO-Shodan-codex/scripts/validate.sh)
- **Mechanism**: Verifies environment dependencies (`python3`, `curl`, and optional tooling such as `nuclei` and `httpx`) and API keys (such as `SHODANAPI` and optionally Cloudflare details). 
- **Orchestration**: Ensures the workspace context and target inputs are formatted correctly before starting execution.

### Phase 2: Multi-Source Host Discovery
- **Commands**: [scripts/orchestrate.py](file:///tmp/C3PO-Shodan-codex/scripts/orchestrate.py) invoking [pipeline/shodan_adapter.py](file:///tmp/C3PO-Shodan-codex/pipeline/shodan_adapter.py)
- **Mechanism**: Interrogates Shodan's DNS API for current and historical records, runs Shodan search with `hostname:*.target`, adds `subfinder -d target` and `chaos-client -d target` hostnames when installed, resolves hostnames locally, enriches resolved IPs with Shodan host details, and keeps duplicate DNS/IP evidence from inflating risk scores.
- **Orchestration**: Resolves domain listings and catalogs active hostnames for targeting. Candidate expansion is intentionally permissive; false positives are acceptable when they are labeled as evidence sources and can be reviewed downstream.

### Phase 2b: Port Evidence Expansion
- **Commands**: Shodan host enrichment and optional `nmap`
- **Mechanism**: Merges open ports from Shodan host data with `nmap -Pn --top-ports <n>` output for resolved IPs. nmap-derived ports are folded into host risk scoring, Nuclei target generation, and the final inventory.
- **Orchestration**: Provides a second check for services that Shodan may have missed or has not indexed recently.

### Phase 3: TXT & Takeover Enrichment
- **Commands**: [scripts/txtfinder.py](file:///tmp/C3PO-Shodan-codex/scripts/txtfinder.py)
- **Mechanism**: Inspects TXT records, resolves CNAME paths, and parses provider-linked DNS strings to detect subdomains dangling on third-party service providers (like AWS, Azure, Shopify, GitHub Pages).
- **Orchestration**: Flags targets with high takeover risk by matching signature fragments.

### Phase 4: Targeted Vulnerability Scanning
- **Command**: `nuclei`
- **Mechanism**: Feeds prioritized reachable web targets plus bounded protocol targets derived from known open ports into `nuclei`. Defaults scan tags `misconfig,exposure,takeover,cve,tech,default-login,ssl,tls,dns,network` at `critical,high,medium,low` severity.
- **Orchestration**: Automates active scanning selectively while allowing longer, broader principal-researcher review runs.

### Phase 5: Visual Evidence Capture
- **Commands**: [scripts/capture-screenshots.py](file:///tmp/C3PO-Shodan-codex/scripts/capture-screenshots.py) (or the Cloudflare Parallel Scanner script)
- **Mechanism**: Captures visual proof of reachable HTTP/S hosts. It prioritizes Cloudflare's URL Scanner API for headless capture and falls back to local web engines (Chrome, Edge, Chromium, or `wkhtmltoimage`).
- **Orchestration**: Creates a screenshot index of reachable interfaces to assist human review.

### Phase 6: Report Synthesis
- **Commands**: [scripts/render-report.py](file:///tmp/C3PO-Shodan-codex/scripts/render-report.py)
- **Mechanism**: Aggregates all JSON outputs, Nuclei scan records, CNAME findings, and screenshot paths.
- **Orchestration**: Generates an interactive, offline-ready HTML dashboard (`output/report.html`) and structured Markdown reports (`runtime/reports/`).

---

### Codex and Agent Integration
While the pipeline execution is structured and deterministic to preserve reproducibility, the workflow is designed to be operated and maintained through **OpenAI Codex / Codex CLI** agents such as the `C3PO-shodan` agent.
1. **Agent Guidance**: The pipeline relies on agent instructions ([AGENTS.md](file:///tmp/C3PO-Shodan-codex/AGENTS.md) and workflow-specific `SKILL.md` files) to orchestrate and patch behavior safely.
2. **Context Enrichment**: Shell scripts (like [scripts/fetch-context.sh](file:///tmp/C3PO-Shodan-codex/scripts/fetch-context.sh)) keep track of active rules, making the entire workspace navigable and controllable by LLM operators using Codex-style commands.
3. **Runtime Dependency**: Codex is not invoked by `run.sh`; `C3PO_CODEX_MODEL`, `CODEX_MODEL`, `C3PO_CODEX_REASONING_EFFORT`, and `C3PO_CODEX_FAST_MODE` are optional operator-context variables only.

### Codex Model Menu

When stdin/stdout are interactive and no model is preconfigured, `run.sh` prompts for:

| Menu Choice | Model | Effort | Fast Mode |
| --- | --- | --- | --- |
| 1 | `gpt-5.5` | `low` | `true` |
| 2 | `gpt-5.5` | `medium` | `true` |
| 3 | `gpt-5.5` | `medium` | `false` |
| 4 | `gpt-5.4` | `high` | `false` |
| 5 | `gpt-5.4` | `medium` | `false` |
| 6 | `gpt-5.4` | `low` | `true` |
| 7 | `gpt-5.4-mini` | `high` | `false` |
| 8 | `gpt-5.4-mini` | `medium` | `true` |
| 9 | `gpt-5.4-mini` | `low` | `true` |
| c | custom | custom | custom |
| 0 | unset | unset | unset |

Use `--no-model-prompt` or `C3PO_MODEL_PROMPT=never` for CI and scheduled runs.

## Configuration

### Common runtime knobs

Defaults come from [`config/config.yaml`](config/config.yaml).

| Key | Default | Purpose |
| --- | --- | --- |
| `shodan_dns_page_limit` | `12` | Limit Shodan DNS paging per mode. |
| `shodan_search_enabled` | `true` | Enable Shodan search for `hostname:*.target`. |
| `shodan_search_page_limit` | `5` | Limit Shodan search pages for hostname expansion. |
| `shodan_host_enrichment_limit` | `100` | Cap Shodan host detail enrichment. |
| `subfinder_timeout_seconds` | `900` | Timeout for `subfinder -d target -all`. |
| `chaos_enabled` | `true` | Enable `chaos-client -d target` discovery when installed. |
| `chaos_timeout_seconds` | `900` | Timeout for chaos-client discovery. |
| `dns_resolve_limit` | `500` | Cap local DNS resolution of discovered hostnames before Shodan host enrichment. |
| `max_hosts_for_http_probe` | `250` | Limit HTTP probing volume. |
| `report_host_limit` | `250` | Limit host cards retained in the report payload. |
| `nmap_enabled` | `true` | Enable local nmap port discovery when installed. |
| `nmap_target_limit` | `100` | Cap resolved IPs scanned by nmap. |
| `nmap_top_ports` | `1000` | nmap top-port profile. |
| `nmap_timeout_seconds` | `900` | Per-IP nmap timeout. |
| `nmap_timing` | `T3` | nmap timing profile passed as `-T3` by default. |
| `nmap_concurrency` | `4` | Parallel nmap workers. |
| `nuclei_enabled` | `true` | Enable or disable the Nuclei phase. |
| `nuclei_target_limit` | `250` | Cap prioritized web target selection before protocol-derived additions. |
| `nuclei_network_target_limit` | `150` | Cap protocol targets generated from open ports. |
| `nuclei_tags` | `misconfig,exposure,takeover,cve,tech,default-login,ssl,tls,dns,network` | Template tags passed to Nuclei. |
| `nuclei_severities` | `critical,high,medium,low` | Nuclei severities included in JSONL findings. |
| `max_screenshots` | `50` | Limit screenshot captures. |
| `screenshot_timeout_seconds` | `90` | Local screenshot timeout. |

### Detailed setup

<details>
<summary><strong>Cloudflare URL Scanner setup</strong></summary>

For better screenshots and URL intelligence, create an API token at `https://dash.cloudflare.com/profile/api-tokens` with:

- `Account -> Cloudflare Radar:Read`
- `Account -> URL Scanner:Read`
- `Account -> URL Scanner:Edit`

Then add:

```bash
CF_ACCOUNT_ID=your_account_id
CF_API_TOKEN=your_api_token
```

Legacy global-key auth is also supported:

```bash
CF_ACCOUNT_ID=your_account_id
CF_EMAIL=your_cloudflare_email
CF_API_KEY=your_global_api_key
```

</details>

<details>
<summary><strong>Python requirements</strong></summary>

The Python code uses the standard library. A minimal [`requirements.txt`](requirements.txt) is included for automation compatibility:

```bash
python3 -m pip install -r requirements.txt
```

</details>

## Outputs

After a run, expect these primary artifacts:

| Path | Description |
| --- | --- |
| `output/attack_surface_<target>_<date>.json` | Raw collected attack-surface payload. |
| `output/attack_surface_<target>_<date>.html` | Self-contained HTML dashboard. |
| `output/discovery_audit_<target>_<date>.json` | Host-source and port-coverage audit emitted after discovery. |
| `runtime/reports/attack_surface_<target>_<date>.md` | Markdown report. |
| `output/nuclei_<target>_<date>.jsonl` | Nuclei findings for scanned web and protocol targets. |
| `output/attack_surface_<target>_<date>_screenshots.json` | Screenshot manifest. |
| `attack_surface_latest.html` | Convenience copy of the latest HTML report. |

## Project Layout

| Path | Role |
| --- | --- |
| [`bin/run.sh`](bin/run.sh) | Main entrypoint and phase orchestration. |
| [`install.sh`](install.sh) | Preflight checks for tools and credentials. |
| [`scripts/orchestrate.py`](scripts/orchestrate.py), [`pipeline/shodan_adapter.py`](pipeline/shodan_adapter.py), [`subtaker.py`](subtaker.py) | Shodan/DNS collection and enrichment used by `run.sh`. |
| [`scripts/capture-screenshots.py`](scripts/capture-screenshots.py) | Screenshot capture with local tooling. |
| [`scripts/render-report.py`](scripts/render-report.py) | Markdown and HTML report rendering. |
| [`docs/architecture.md`](docs/architecture.md) | High-level architecture notes. |
| [`docs/flow.md`](docs/flow.md) | End-to-end execution flow. |

## Notes

- Screenshot capture is best-effort and is skipped automatically when tooling is unavailable.
- If Cloudflare rate-limits or credentials are missing, the pipeline falls back to local screenshot capture.
- If `nuclei` is unavailable or no reachable web targets exist, the rest of the collection and reporting pipeline can still complete.
- Output is generated locally for inspection; the repo does not create a separate CISO-summary text artifact.
