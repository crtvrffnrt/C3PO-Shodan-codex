# Rendering Skill

Use this phase to turn collected JSON into readable Markdown and a self-contained HTML operator dashboard.

## Primary Goal

- Render complete output even when screenshots or enrichment are missing.
- Escape all untrusted input before it reaches HTML.
- Keep the markdown and HTML outputs aligned in structure and naming.

## Workflow

1. Inspect `scripts/render-report.py`, `pipeline/reporting.py`, `docs/style.md`, and `docs/index-ref.html`.
2. Verify output filenames, report structure, and embedded assets before editing the renderer.
3. Preserve the existing visual language unless the task explicitly asks for a design change.
4. Treat screenshot entries and external metadata as optional inputs, not hard requirements.

## Coding Rules

- Use `apply_patch` for edits.
- Prefer small, local renderer changes over broad template rewrites.
- Keep HTML self-contained.
- Do not overwrite unrelated site assets.

## Good Targets

- `scripts/render-report.py`
- `pipeline/reporting.py`
- `docs/style.md`
- `docs/index-ref.html`

## Completion Check

- Rendering succeeds with no screenshots.
- Broken optional artifacts do not crash output generation.
- HTML remains readable offline.
