#!/bin/bash
# From a workstation: copies the five components to the VPS
# ($CROSS_HOME/src/<component>, no git there) and runs run.sh there with
# the arguments given. The components under test are exported at their
# committed HEAD (git archive); the two MailOS worktrees are copied as they
# are on disk, so a change can be tried before it is committed.
#
#   IAM_SERVER_SRC   default: the IAM server's mailos-platform-plane worktree
#   IAM_CONSOLE_SRC  default: the IAM console's mailos-platform-plane worktree
#   ACS_SRC          default: the ACS mailos-platform-subjects worktree
#   MAILOS_CONSOLE_SRC default: the MailOS console's platform-phase1-cross worktree
#   CROSS_VPS        default ansible@13.140.212.153
#   CROSS_HOME       default /opt/mailos-p1-test/cross
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PROD=$(cd "$ROOT/../../../../.." && pwd)
IAM_SERVER_SRC=${IAM_SERVER_SRC:-$PROD/iam/server/.claude/worktrees/mailos-platform-plane}
IAM_CONSOLE_SRC=${IAM_CONSOLE_SRC:-$PROD/iam/client/.claude/worktrees/mailos-platform-plane}
ACS_SRC=${ACS_SRC:-$PROD/acs/server/.claude/worktrees/mailos-platform-subjects}
MAILOS_CONSOLE_SRC=${MAILOS_CONSOLE_SRC:-$PROD/mailOS/client/.claude/worktrees/platform-phase1-cross}
VPS=${CROSS_VPS:-ansible@13.140.212.153}
CROSS_HOME=${CROSS_HOME:-/opt/mailos-p1-test/cross}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ssh "$VPS" "mkdir -p '$CROSS_HOME/src'"
# Build output on the VPS (node_modules, .next) survives a push.
keep=(--exclude node_modules --exclude .next --exclude .git --exclude .claude --exclude 'e2e/.work' --exclude 'e2e/.results'
  --exclude 'e2e/cross/.results' --exclude 'e2e/.state')

exported() { # name source: the committed HEAD
  local name=$1 src=$2
  mkdir -p "$TMP/$name"
  git -C "$src" archive HEAD | tar -x -C "$TMP/$name"
  git -C "$src" rev-parse --short HEAD >"$TMP/$name/.commit"
  rsync -az --delete "${keep[@]}" "$TMP/$name/" "$VPS:$CROSS_HOME/src/$name/"
  echo "push: $name at $(cat "$TMP/$name/.commit")"
}

ondisk() { # name source: the working tree
  local name=$1 src=$2
  rsync -az --delete "${keep[@]}" --exclude '/bin' --exclude '*.test' "$src/" "$VPS:$CROSS_HOME/src/$name/"
  printf '%s%s\n' "$(git -C "$src" rev-parse --short HEAD)" "$(git -C "$src" diff --quiet HEAD -- . && echo '' || echo '+dirty')" |
    ssh "$VPS" "cat > '$CROSS_HOME/src/$name/.commit'"
  echo "push: $name (working tree)"
}

exported iam-server "$IAM_SERVER_SRC"
exported iam-console "$IAM_CONSOLE_SRC"
exported acs "$ACS_SRC"
ondisk mailos-server "$ROOT"
ondisk mailos-console "$MAILOS_CONSOLE_SRC"

if [ $# -gt 0 ]; then
  ssh "$VPS" "cd '$CROSS_HOME/src/mailos-server/e2e/cross' && CROSS_HOME='$CROSS_HOME' ./run.sh $*"
fi
