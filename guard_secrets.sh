#!/usr/bin/env bash
# Shared plaintext-secret guard used by multiple repos via pre-commit.
#
# Usage: guard_secrets.sh [--names EXTRA1,EXTRA2] [--allow VAL1,VAL2] <files...>
#   --names  comma-separated extra secret variable names (e.g. ONSHAPE_SECRET_KEY)
#   --allow  comma-separated extra allowed placeholder values
#
# Generic secret names are always matched: API_KEY / ACCESS_TOKEN /
# CLIENT_SECRET / PRIVATE_KEY / PASSWORD.
set -euo pipefail

EXTRA_NAMES=""
EXTRA_ALLOW=""
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --names) EXTRA_NAMES="$2"; shift 2 ;;
        --allow) EXTRA_ALLOW="$2"; shift 2 ;;
        *) POSITIONAL+=("$1"); shift ;;
    esac
done
FILES=("${POSITIONAL[@]}")

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# Patterns that match assignment of a secret-looking variable name
SECRET_NAME_PAT="(API[_-]?KEY|ACCESS[_-]?TOKEN|CLIENT[_-]?SECRET|PRIVATE_KEY|PASSWORD"
if [[ -n "$EXTRA_NAMES" ]]; then
    SECRET_NAME_PAT="${SECRET_NAME_PAT}|${EXTRA_NAMES//,/|}"
fi
SECRET_NAME_PAT="${SECRET_NAME_PAT})"
ASSIGN_PAT="^[[:space:]]*(export[[:space:]]+)?${SECRET_NAME_PAT}[[:space:]]*[:=][[:space:]]*(.+)[[:space:]]*$"

# Values that are explicitly allowed (placeholders / empty). The leading pipe
# adds an empty alternative so "KEY: \"\"" (stripped to empty) is allowed.
ALLOWED_VALUES="|replace_me|changeme|example|placeholder|DEMO_KEY|null|None|test-token|dummy|redacted|your_key|your_password|your_private_key|your_user_id|"
if [[ -n "$EXTRA_ALLOW" ]]; then
    ALLOWED_VALUES="${ALLOWED_VALUES}|${EXTRA_ALLOW//,/|}"
fi

# File extensions to skip (binary-like)
SKIP_EXT_PAT='\.(png|jpg|jpeg|gif|bmp|tif|tiff|ico|pdf|docx|zip|7z|tar|gz|whl|exe|dll|pyd|so|jar)$'

# Paths that are explicitly allowed
ALLOW_PATH_PAT='(\.env\.example|\.example\.(yaml|yml|json|env)|\.[tT]emplate\.(yaml|yml|json|env)|\.[sS]ops\.(yaml|yml|json|env)|secrets/README\.md|docs/SECRETS\.md|README\.md)$'

if [[ "${#FILES[@]}" -eq 0 ]]; then
    mapfile -t FILES < <(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null || true)
fi

findings=()

for raw in "${FILES[@]}"; do
    [[ -z "$raw" ]] && continue
    candidate="$raw"
    [[ "$candidate" != /* ]] && candidate="$REPO_ROOT/$candidate"
    [[ -f "$candidate" ]] || continue

    relative="${candidate#"$REPO_ROOT/"}"

    # Skip allowed paths and binary-like extensions
    echo "$relative" | grep -qiE "$ALLOW_PATH_PAT" && continue
    echo "$relative" | grep -qiE "$SKIP_EXT_PAT"   && continue

    # Skip files that aren't valid UTF-8 text (heuristic: check with file)
    file_type="$(file -b --mime-type "$candidate" 2>/dev/null || true)"
    case "$file_type" in
        text/*|application/json|application/x-yaml|application/xml) ;;
        *) continue ;;
    esac

    lineno=0
    while IFS= read -r line; do
        ((lineno++)) || true
        if [[ "$line" =~ $ASSIGN_PAT ]]; then
            value="${BASH_REMATCH[2]}"
            value="$(echo "$value" | sed 's/[[:space:]]*#.*$//' | sed 's/,$//' | xargs)"
            if echo "$value" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*(\s*\|\s*[A-Za-z_][A-Za-z0-9_]*)*\s*='; then
                value="$(echo "$value" | sed -E 's/^[A-Za-z_][A-Za-z0-9_]*(\s*\|\s*[A-Za-z_][A-Za-z0-9_]*)*\s*=[[:space:]]*//' | sed 's/,$//' | xargs)"
            fi
            value="${value//\"/}"
            value="${value//\'/}"
            # Skip empty or placeholder values
            echo "|$value|" | grep -qiE "^\\|(${ALLOWED_VALUES})\\|$" && continue
            # Skip angle-bracket placeholders (e.g. <Cloudflare secret>)
            echo "$value" | grep -qE '^<[^<>]*>$' && continue
            # Skip shell/env variable references
            echo "$value" | grep -qE '^\$\{?[A-Z0-9_]+}?$' && continue
            # Skip GitHub Actions expressions (${{ secrets.X }})
            echo "$value" | grep -qE '^\$\{\{[[:space:]]*secrets\.[A-Za-z0-9_]+[[:space:]]*\}\}$' && continue
            # Skip shell default templates (${VAR:-default})
            echo "$value" | grep -qE '\$\{[A-Za-z0-9_]+(:|-)' && continue
            echo "$value" | grep -qE '^(os\.getenv|getenv)\(' && continue
            echo "$value" | grep -qE '^[a-zA-Z_][a-zA-Z0-9_.]*\(os\.getenv\(' && continue
            echo "$value" | grep -qE '__import__\(' && continue
            echo "$value" | grep -qE '^[a-zA-Z_][a-zA-Z0-9_]*\(' && continue
            echo "$value" | grep -qE '_resolve_credential\(' && continue
            echo "$value" | grep -qE '\b_resolve\(' && continue
            echo "$value" | grep -qE '_resolved_value\(' && continue
            echo "$value" | grep -qE '\bget_[a-z_]+_token\(' && continue
            echo "$value" | grep -qE '^[a-z_][a-z0-9_]*$' && continue
            echo "$value" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*(\.[a-z][a-z0-9_]*)+$' && continue
            echo "$value" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*(\s*\|\s*[A-Za-z_][A-Za-z0-9_]*)*$' && continue
            echo "$value" | grep -qE '^[A-Za-z_][A-Za-z0-9_.]*\.get\(' && continue
            echo "$value" | grep -qE '^Your ' && continue
            [[ "${#value}" -lt 8 ]] && continue
            findings+=("${relative}:${lineno} possible plaintext credential")
        fi
    done < "$candidate"
done

if [[ "${#findings[@]}" -gt 0 ]]; then
    echo "Plaintext credential candidates found:" >&2
    printf '  %s\n' "${findings[@]}" >&2
    echo "Move real credentials to the encrypted secrets/*.sops.yaml bundle or the gitignored repo-root .env." >&2
    exit 1
fi

exit 0
