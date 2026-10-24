#!/usr/bin/env bash
# Fetch the tracked upstream and apply only clean fast-forward updates.
set -Eeuo pipefail

readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

log() {
    printf '\n==> %s\n' "$*"
}

die() {
    printf 'update.sh: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ./update.sh

Check the current branch's configured upstream for new Celsius code. If the
local branch is behind, update it with a fast-forward-only merge.

The worktree must be clean when an update is available. Tracked modifications
and untracked files are never stashed, deleted, or overwritten. Ahead and
diverged branches are left unchanged for manual reconciliation.

This script fetches from the configured Git remote but never commits or pushes.
It does not run the installer or restart the server. After runtime-file changes,
run ./install.sh; restart a running server when it is idle.
EOF
}

main() {
    case "${1:-}" in
        -h|--help)
            usage
            return
            ;;
        "") ;;
        *) die "unknown argument: $1 (use --help)" ;;
    esac

    command -v git >/dev/null 2>&1 || die "Git is required"
    [[ "$(git -C "$ROOT_DIR" rev-parse --is-inside-work-tree 2>/dev/null)" == "true" ]] \
        || die "the script is not inside a Git checkout"

    local branch upstream remote
    branch="$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD)"
    [[ "$branch" != "HEAD" ]] || die "check out a branch before updating"
    upstream="$(git -C "$ROOT_DIR" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)" \
        || die "the current branch has no upstream (for example: git branch --set-upstream-to=origin/main)"
    remote="$(git -C "$ROOT_DIR" config --get "branch.$branch.remote")" \
        || die "cannot determine the remote for branch $branch"

    log "Checking $upstream for updates"
    git -C "$ROOT_DIR" fetch --prune "$remote" \
        || die "fetch failed; the working tree was not changed"

    local local_sha remote_sha merge_base
    local_sha="$(git -C "$ROOT_DIR" rev-parse HEAD)"
    remote_sha="$(git -C "$ROOT_DIR" rev-parse "$upstream" 2>/dev/null)" \
        || die "upstream $upstream disappeared after fetching"
    merge_base="$(git -C "$ROOT_DIR" merge-base HEAD "$upstream")"

    if [[ "$local_sha" == "$remote_sha" ]]; then
        log "Celsius is up to date ($(git -C "$ROOT_DIR" rev-parse --short HEAD))"
        return
    fi
    if [[ "$merge_base" == "$remote_sha" ]]; then
        log "The local branch is ahead of $upstream; nothing to update"
        return
    fi
    if [[ "$merge_base" != "$local_sha" ]]; then
        die "local and upstream history have diverged; reconcile them manually before updating"
    fi

    if [[ -n "$(git -C "$ROOT_DIR" status --porcelain)" ]]; then
        die "an update is available, but the worktree contains uncommitted or untracked files; commit or stash them, then rerun"
    fi

    log "Updating $(git -C "$ROOT_DIR" rev-parse --short HEAD) to $(git -C "$ROOT_DIR" rev-parse --short "$upstream")"
    git -C "$ROOT_DIR" merge --ff-only "$upstream"
    log "Updated to $(git -C "$ROOT_DIR" rev-parse --short HEAD)"

    local path runtime_changed=0
    while IFS= read -r path; do
        case "$path" in
            pyproject.toml|uv.lock|requirements.txt|install.sh)
                runtime_changed=1
                ;;
        esac
    done < <(git -C "$ROOT_DIR" diff --name-only "$local_sha" "$remote_sha" --)

    if (( runtime_changed )); then
        printf '\nRuntime files changed; refresh the local environment with:\n'
        printf '  cd %q && ./install.sh\n' "$ROOT_DIR"
    fi
    printf '\nIf the server is running, restart it when idle:\n'
    printf '  cd %q && ./kill.sh && ./run.sh\n' "$ROOT_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
