# Validation Skill

Use this phase to make the run fail fast on missing prerequisites and bad inputs before any collection starts.

## Primary Goal

- Confirm required files, commands, and credentials exist before launching the pipeline.
- Keep validation strict for hard dependencies and permissive for optional augmentation.
- Align domain parsing and target normalization with the shell entrypoint.

## Workflow

1. Inspect `scripts/validate.sh`, `scripts/common.sh`, and `config/config.yaml`.
2. Verify every hard dependency referenced by the run path exists in the repository.
3. If a check needs to change, update the shell script and any docs that describe the contract.
4. Prefer clear error messages over silent fallback when a required artifact is missing.

## Coding Rules

- Use `apply_patch` for edits.
- Do not introduce new validation branches unless they are backed by an actual runtime dependency.
- Keep optional tooling checks separate from required preflight checks.
- Preserve deterministic exit behavior.

## Good Targets

- `scripts/validate.sh`
- `scripts/common.sh`
- `install.sh`
- `README.md`

## Completion Check

- A missing required file, binary, or secret fails with a direct message.
- Optional tooling only reduces capability.
