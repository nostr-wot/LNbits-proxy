#!/usr/bin/env bash
#
# Deploy the newest published release, if it is not already live.
#
# The box pulls; nothing is pushed to it. There is no inbound access, no deploy key
# and no host address anywhere in this public repository, and a compromise of the
# GitHub repository cannot reach this machine except by publishing a release that
# this script then refuses or accepts on its own terms.
#
# Run from the checkout on a timer. Does nothing and says nothing when already
# current, so a frequent timer stays cheap and the log stays readable.
#
#   ./scripts/auto-deploy.sh              deploy the current release if needed
#   ZAPS_DRY_RUN=1 ./scripts/auto-deploy.sh   decide, report, change nothing
#
# What it refuses, which is the point:
#   - a draft or pre-release
#   - a tag that is not exactly vMAJOR.MINOR.PATCH
#   - a tag that does not exist here after fetching
#   - a tag outside the trusted history (default origin/main), so a tag pushed onto
#     a side branch cannot put unreviewed code into production
# A failed deploy is not recorded, so the next tick tries again rather than
# believing a version is live that is not.
set -euo pipefail

REPO="${ZAPS_REPO:-nostr-wot/LNbits-proxy}"
STATE_FILE="${ZAPS_STATE_FILE:-/srv/zaps-provision/deployed-version}"
TRUSTED_REF="${ZAPS_TRUSTED_REF:-origin/main}"
DEPLOY_CMD="${ZAPS_DEPLOY_CMD:-./deploy.sh}"
RELEASE_FETCH="${ZAPS_RELEASE_FETCH:-curl -fsSL -m 20 -H 'Accept: application/vnd.github+json' https://api.github.com/repos/${REPO}/releases/latest}"
LOCK_DIR="${ZAPS_LOCK_DIR:-${TMPDIR:-/tmp}/zaps-auto-deploy.lock}"

cd "$(dirname "$0")/.."

note() { printf '[auto-deploy] %s\n' "$*"; }
fail() { printf '[auto-deploy] %s\n' "$*" >&2; exit 1; }

# One at a time. A timer firing during a deploy is ordinary, not an error: mkdir is
# the atomic test-and-set that works the same on every box this might run on.
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  if [ -r "$LOCK_DIR/pid" ] && ! kill -0 "$(cat "$LOCK_DIR/pid" 2>/dev/null)" 2>/dev/null; then
    note "clearing a lock left by a dead run"
    rm -rf "$LOCK_DIR"
    mkdir "$LOCK_DIR" || fail "cannot take the lock at $LOCK_DIR"
  else
    note "another run holds the lock; nothing to do"
    exit 0
  fi
fi
echo "$$" > "$LOCK_DIR/pid"
trap 'rm -rf "$LOCK_DIR"' EXIT

release_json="$(eval "$RELEASE_FETCH")" || fail "cannot read the release feed"

# Parsed by node rather than by grep: a hand-rolled match on someone else's JSON is
# how a prerelease flag gets missed. Prints the tag only if it is one we would ever
# deploy, and the shape is checked here so the rest of the script handles a known
# good string.
tag="$(printf '%s' "$release_json" | node -e '
  let raw = "";
  process.stdin.on("data", c => raw += c).on("end", () => {
    let release;
    try { release = JSON.parse(raw); } catch { console.error("release feed is not JSON"); process.exit(1); }
    const tag = release?.tag_name;
    if (typeof tag !== "string" || !/^v\d+\.\d+\.\d+$/.test(tag)) {
      console.error(`release tag is not a plain version: ${JSON.stringify(tag)}`);
      process.exit(1);
    }
    if (release.draft === true) { console.error(`${tag} is still a draft`); process.exit(1); }
    if (release.prerelease === true) { console.error(`${tag} is a pre-release`); process.exit(1); }
    process.stdout.write(tag);
  });
')" || fail "refusing this release"

current="$(cat "$STATE_FILE" 2>/dev/null || true)"
if [ "$current" = "$tag" ]; then
  exit 0
fi

note "current release is $tag, deployed is ${current:-none}"

if [ -z "${ZAPS_SKIP_FETCH:-}" ]; then
  git fetch --quiet --tags --prune origin || fail "cannot fetch from origin"
fi

git rev-parse -q --verify "refs/tags/${tag}" >/dev/null \
  || fail "$tag does not exist here even after fetching"

# The release says what to deploy; this says whether that commit is one that went
# through the branch everything is reviewed on. Anyone able to push a tag could
# otherwise point production at any commit in the repository.
git merge-base --is-ancestor "${tag}^{commit}" "$TRUSTED_REF" 2>/dev/null \
  || fail "$tag is not in the trusted history ($TRUSTED_REF); refusing to deploy it"

if [ -n "${ZAPS_DRY_RUN:-}" ]; then
  note "would deploy $tag with: $DEPLOY_CMD --ref $tag"
  exit 0
fi

note "deploying $tag"
if ! "$DEPLOY_CMD" --ref "$tag"; then
  # Deliberately not recorded: deploy.sh leaves the previous version serving when it
  # aborts, and the next tick should try again rather than assume this one is live.
  fail "deploying $tag failed; $(basename "$DEPLOY_CMD") reports the detail above"
fi

mkdir -p "$(dirname "$STATE_FILE")"
printf '%s\n' "$tag" > "$STATE_FILE"
note "$tag is live"
