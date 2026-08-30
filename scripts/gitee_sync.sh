#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/gitee_sync.sh [options]

Mirror the current repository to Gitee.

Options:
  --dry-run              Validate configuration and print the command without pushing
  --source-remote NAME   Source Git remote (default: origin)
  --source-ref REF       Source branch to validate (default: main)
  --gitee-owner NAME     Gitee owner or organization (default: GITEE_OWNER)
  --gitee-repo NAME      Gitee repository name (default: GITEE_REPO)
  --gitee-host HOST      Gitee hostname (default: gitee.com)
  -h, --help             Show this help

Required environment:
  GITEE_TOKEN            Gitee personal access token
EOF
}

dry_run=false
source_remote="origin"
source_ref="main"
gitee_owner="${GITEE_OWNER:-}"
gitee_repo="${GITEE_REPO:-}"
gitee_host="${GITEE_HOST:-gitee.com}"

while (($# > 0)); do
    case "$1" in
        --dry-run)
            dry_run=true
            shift
            ;;
        --source-remote)
            (($# >= 2)) || { echo "--source-remote requires a value" >&2; exit 2; }
            source_remote="$2"
            shift 2
            ;;
        --source-ref)
            (($# >= 2)) || { echo "--source-ref requires a value" >&2; exit 2; }
            source_ref="$2"
            shift 2
            ;;
        --gitee-owner)
            (($# >= 2)) || { echo "--gitee-owner requires a value" >&2; exit 2; }
            gitee_owner="$2"
            shift 2
            ;;
        --gitee-repo)
            (($# >= 2)) || { echo "--gitee-repo requires a value" >&2; exit 2; }
            gitee_repo="$2"
            shift 2
            ;;
        --gitee-host)
            (($# >= 2)) || { echo "--gitee-host requires a value" >&2; exit 2; }
            gitee_host="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

gitee_token="${GITEE_TOKEN:-}"
if [[ -z "$gitee_token" ]]; then
    echo "GITEE_TOKEN is required" >&2
    exit 1
fi
if [[ "$gitee_token" =~ [[:space:]] ]]; then
    echo "GITEE_TOKEN must not contain whitespace" >&2
    exit 1
fi
if [[ -z "$gitee_owner" ]]; then
    echo "Gitee owner is required (GITEE_OWNER or --gitee-owner)" >&2
    exit 1
fi
if [[ -z "$gitee_repo" ]]; then
    echo "Gitee repository is required (GITEE_REPO or --gitee-repo)" >&2
    exit 1
fi
if [[ ! "$gitee_host" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
    echo "Invalid Gitee hostname: $gitee_host" >&2
    exit 1
fi
if [[ ! "$gitee_owner" =~ ^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]; then
    echo "Invalid Gitee owner path: $gitee_owner" >&2
    exit 1
fi
if [[ ! "$gitee_repo" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "Invalid Gitee repository name: $gitee_repo" >&2
    exit 1
fi

command -v git >/dev/null 2>&1 || {
    echo "git is required" >&2
    exit 1
}

if ! git remote get-url "$source_remote" >/dev/null 2>&1; then
    echo "Source remote does not exist: $source_remote" >&2
    exit 1
fi

source_commit="$(git rev-parse --verify "${source_ref}^{commit}")"
destination_url="https://oauth2@${gitee_host}/${gitee_owner}/${gitee_repo}.git"

cat <<EOF
Source remote: ${source_remote}
Source ref: ${source_ref}
Source commit: ${source_commit}
Destination: https://${gitee_host}/${gitee_owner}/${gitee_repo}.git
EOF

if [[ "$dry_run" == true ]]; then
    printf '[dry-run] git push --mirror %q\n' "$destination_url"
    exit 0
fi

credential_helper='!f() { printf "username=oauth2\npassword=%s\n" "$GITEE_TOKEN"; }; f'
exec git -c "credential.helper=${credential_helper}" push --mirror "$destination_url"
