# Collection Skill

Use this phase to trace the data path from domain input to collected host inventory.

## Primary Goal

- Produce deterministic DNS, Shodan, and web-enrichment artifacts.
- Keep evidence, derived scoring, and operational metadata separate.
- Avoid duplicate probes that do not add new signal.

## Workflow

1. Inspect `scripts/collect-attack-surface.py`, `scripts/orchestrate.py`, `pipeline/orchestrator.py`, and `pipeline/shodan_adapter.py`.
2. Verify the file contracts used by `scripts/validate.sh` still exist and are consumed correctly.
3. If you need new collection behavior, thread the change through config, runtime output, and report shaping together.
4. Prefer bounded changes that improve signal quality or reliability.

## Coding Rules

- Use `apply_patch` for edits.
- Keep collection deterministic where possible.
- Do not broaden scans or lookups unless the output will be consumed downstream.
- Preserve canonical formatting for IPs, CIDR/network hints, and hostnames.

## Good Targets

- `scripts/collect-attack-surface.py`
- `scripts/orchestrate.py`
- `scripts/domain_lookup.py`
- `scripts/txtfinder.py`
- `pipeline/discovery.py`
- `pipeline/shodan_adapter.py`

## Completion Check

- Collection output remains stable and machine-readable.
- New knobs actually affect the collection boundary.
