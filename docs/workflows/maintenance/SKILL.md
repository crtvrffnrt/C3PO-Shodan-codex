# Maintenance Skill

Use this phase to keep the repo coherent when shell, Python, config, and docs change together.

## Primary Goal

- Keep the file contracts, docs, and execution path in sync.
- Update all layers together when a behavior contract changes.
- Avoid drift between the repo guidance and shipped CLI behavior.

## Workflow

1. Inspect the shell entrypoints, Python pipeline, and workflow docs before editing.
2. Trace any changed config key through the scripts that read it.
3. If you rename or move a file, update every local reference in the same change.
4. Prefer additive changes over broad rewrites.

## Coding Rules

- Use `apply_patch` for edits.
- Do not revert user changes.
- Keep comments short and only add them when they explain non-obvious behavior.
- Preserve ASCII unless a file already uses another character set.

## Good Targets

- `AGENTS.md`
- `docs/architecture.md`
- `docs/flow.md`
- `scripts/common.sh`
- `scripts/validate.sh`
- `bin/run.sh`

## Completion Check

- Documented defaults match implementation.
- Path changes are reflected everywhere they are used.
