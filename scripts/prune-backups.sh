#!/usr/bin/env bash
#
# Keep the newest few `*.bak-<stamp>` copies in a directory, per file, and delete the
# rest. Deploys used to be occasional and manual; on a timer their backups accumulate
# until something fills the disk.
#
#   ./scripts/prune-backups.sh <dir> [keep]
#
# Written as a script with tests because the first version of this was three inline
# lines in deploy.sh that used `ls <glob> | tail`: under `set -euo pipefail` the glob
# matching nothing made ls exit non-zero, pipefail propagated it, and the deploy died
# after taking its backups and before installing anything.
#
# Backups are selected by NAME, not mtime. The stamp is YYYYmmdd-HHMMSS, so it sorts
# lexically into chronological order, and a restored or touched file cannot reorder
# the history by accident.
set -euo pipefail

dir="${1:-}"
# ${2-10}, not ${2:-10}: an explicitly empty limit means the caller has an unset
# variable, and that should be said out loud rather than silently become 10.
keep="${2-10}"

if [ -z "$dir" ]; then
  echo "usage: prune-backups.sh <dir> [keep]" >&2
  exit 2
fi
if ! printf '%s' "$keep" | grep -qE '^[1-9][0-9]*$'; then
  echo "prune-backups: keep must be a positive whole number, got \"$keep\"" >&2
  exit 2
fi

# Nothing to do rather than an error: the first deploy onto a new box has no
# backup directory yet, and failing here would block it.
[ -d "$dir" ] || exit 0

shopt -s nullglob
backups=("$dir"/*.bak-*)
shopt -u nullglob
[ ${#backups[@]} -gt 0 ] || exit 0

# Grouped by the name before `.bak-`, so a file with two backups does not lose them
# because another file in the same directory has twelve. Done with a sorted list
# rather than an associative array: those need bash 4, and this has to behave the
# same on a developer's machine as on the host.
bases=$(printf '%s\n' "${backups[@]}" | sed 's/\.bak-.*$//' | sort -u)

while IFS= read -r base; do
  [ -n "$base" ] || continue
  shopt -s nullglob
  copies=("$base".bak-*)
  shopt -u nullglob
  total=${#copies[@]}
  [ "$total" -gt "$keep" ] || continue
  # Glob expansion is sorted, and the stamp sorts chronologically, so the oldest are
  # first.
  drop=$(( total - keep ))
  index=0
  while [ "$index" -lt "$drop" ]; do
    rm -f -- "${copies[$index]}"
    index=$(( index + 1 ))
  done
done <<EOF
$bases
EOF
