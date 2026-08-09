# pre-commit-hooks — shared hooks for `~/dev` repos

Canonical home for the reusable pre-commit hooks used across the personal
repos. Reference from any repo's `.pre-commit-config.yaml`:

```yaml
  - repo: /home/angel/dev/pre-commit-hooks
    rev: v1.0.0
    hooks:
      - id: no-plaintext-secrets
        args: [--names, "ONSHAPE_ACCESS_KEY,ONSHAPE_SECRET_KEY"]
      - id: gitleaks-protect
      - id: gitleaks-history
      - id: vulture
        args: [src, --min-confidence=80]
      - id: refurb
        args: [--dont-fix]
      - id: pycycle
        args: [--here]
      - id: radon-cc
        args: [cc, src, -s, -a]
      - id: xenon
        args: [--max-absolute, B, --max-modules, B, --max-average, B, src]
```

Requirements:
- `gitleaks` on PATH (WSL-wide install: `~/.local/bin/gitleaks`).
- `no-plaintext-secrets` needs per-repo `--names` (extra secret variable names,
  comma-separated); generic names (API_KEY / ACCESS_TOKEN / CLIENT_SECRET /
  PRIVATE_KEY / PASSWORD) are always matched.

## Versioning
- Bump `vX.Y.Z` tags on change; pin `rev:` in consuming repos so upgrades are
  deliberate.
- When pushing to GitHub, change the `repo:` path to
  `https://github.com/OomAngel/pre-commit-hooks` and keep the same tags.
