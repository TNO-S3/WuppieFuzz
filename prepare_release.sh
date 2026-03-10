#!/usr/bin/env sh
# prepare_release.sh
#
# Decide next version from CHANGELOG.md or override via --version,
# then update:
#  - CITATION.cff: version: "v<NEW_VERSION>", date-released: "<DATE>"
#  - Cargo.toml:   [package] version = "<NEW_VERSION>"
#  - CHANGELOG.md: reset 'in progress' template and insert '# v<NEW_VERSION> (<DATE>)'
#  - README.md:    replace '# WuppieFuzz v<OLD_VERSION>' with '# WuppieFuzz v<NEW_VERSION>'
#  - LICENSE:      ensure '2021-<RELEASE_YEAR>' exists (update if needed)
#  - Run `cargo generate-lockfile` to refresh Cargo.lock
#
# Rules from '# v1.x (in progress)':
#  - If '## Features' has >0 items -> bump MINOR (x.y+1.0)
#  - Else if '## Fixes' has >0 items -> bump PATCH (x.y.z+1)
#  - If both zero -> error (nothing new to release)
#
# Usage:
#   ./prepare_release.sh [--date YYYY-MM-DD] [--version x.y.z] [--dry-run]
#
# Notes:
#  - Reads current version from Cargo.toml [package] section.
#  - Default DATE = today (local) if --date is not provided.
#  - Requires: awk, grep, cut, date, cargo (unless --dry-run).

set -eu

DATE_OVERRIDE=""
VERSION_OVERRIDE=""
DRY_RUN=0

usage() {
  echo "Usage: $0 [--date YYYY-MM-DD] [--version x.y.z] [--dry-run]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --date)
      [ $# -ge 2 ] || { echo "Missing value for --date" >&2; usage; }
      DATE_OVERRIDE="$2"; shift 2 ;;
    --version)
      [ $# -ge 2 ] || { echo "Missing value for --version" >&2; usage; }
      VERSION_OVERRIDE="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    --help|-h)
      usage ;;
    *)
      echo "Unknown argument: $1" >&2; usage ;;
  esac
done

CITATION_FILE="CITATION.cff"
CARGO_FILE="Cargo.toml"
CHANGELOG_FILE="CHANGELOG.md"
README_FILE="README.md"
LICENSE_FILE="LICENSE"

[ -f "$CITATION_FILE" ]  || { echo "Missing $CITATION_FILE" >&2; exit 1; }
[ -f "$CARGO_FILE" ]     || { echo "Missing $CARGO_FILE" >&2; exit 1; }
[ -f "$CHANGELOG_FILE" ] || { echo "Missing $CHANGELOG_FILE" >&2; exit 1; }
[ -f "$LICENSE_FILE" ]   || { echo "Missing $LICENSE_FILE" >&2; exit 1; }  # required to ensure the year range

# Choose date (default today, strictly YYYY-MM-DD)
if [ -n "$DATE_OVERRIDE" ]; then
  RELEASE_DATE="$DATE_OVERRIDE"
else
  RELEASE_DATE="$(date +%Y-%m-%d)"
fi
case "$RELEASE_DATE" in
  ????-??-??) : ;;
  *) echo "RELEASE_DATE must be YYYY-MM-DD" >&2; exit 1 ;;
esac
RELEASE_YEAR="$(printf '%s' "$RELEASE_DATE" | cut -d- -f1)"

ts() { date +%Y%m%d%H%M%S; }

# --------------------------------------------------------------------
# Read current version from Cargo.toml [package]
# --------------------------------------------------------------------
CURRENT_VERSION="$(
  awk '
    BEGIN{inpkg=0}
    /^\[package\][[:space:]]*$/ {inpkg=1; next}
    /^\[/ && inpkg==1 {inpkg=0}
    inpkg==1 && /^[[:space:]]*version[[:space:]]*=/ {
      if (match($0,/"([^"]+)"/,m)) { print m[1]; exit }
    }
  ' "$CARGO_FILE"
)"

if [ -z "$CURRENT_VERSION" ]; then
  echo "Could not read [package] version from $CARGO_FILE" >&2
  exit 1
fi

case "$CURRENT_VERSION" in
  *[!0-9.]*|'') echo "Current version not in x.y.z form: $CURRENT_VERSION" >&2; exit 1 ;;
esac

X="$(printf "%s" "$CURRENT_VERSION" | cut -d. -f1)"
Y="$(printf "%s" "$CURRENT_VERSION" | cut -d. -f2)"
Z="$(printf "%s" "$CURRENT_VERSION" | cut -d. -f3)"
: "${X:?}"; : "${Y:?}"; : "${Z:?}"

# --------------------------------------------------------------------
# Analyse CHANGELOG.md "in progress" section
# Count '## Features' and '## Fixes' items (non-empty, non-heading lines)
# --------------------------------------------------------------------
ANALYSIS_OUT="$(
awk '
  BEGIN {
    inprog=0; in_feat=0; in_fix=0;
    feat_count=0; fix_count=0;
  }
  # Start of in-progress section
  /^# v1\.x \(in progress\)[[:space:]]*$/ { inprog=1; in_feat=0; in_fix=0; next }
  # Any new top-level version header ends in-progress
  inprog==1 && /^# v[0-9]+\.[0-9]+\.[0-9]+ \(/ { inprog=0; in_feat=0; in_fix=0; }
  # Subsections
  inprog==1 && /^## Features[[:space:]]*$/ { in_feat=1; in_fix=0; next }
  inprog==1 && /^## Fixes[[:space:]]*$/    { in_fix=1; in_feat=0; next }
  inprog==1 && /^## /                      { in_feat=0; in_fix=0; next }

  # Within subsections: count any non-empty, non-heading line
  in_feat==1 {
    line=$0; gsub(/^[ \t]+|[ \t]+$/,"",line)
    if (line != "" && line !~ /^##/ && line !~ /^#/) { feat_count++ }
    next
  }
  in_fix==1 {
    line=$0; gsub(/^[ \t]+|[ \t]+$/,"",line)
    if (line != "" && line !~ /^##/ && line !~ /^#/) { fix_count++ }
    next
  }
  END {
    print "FEATURES_COUNT=" feat_count
    print "FIXES_COUNT=" fix_count
  }
' "$CHANGELOG_FILE"
)"

FEATURES_COUNT="$(printf "%s\n" "$ANALYSIS_OUT" | awk -F= '/^FEATURES_COUNT=/{print $2; exit}')"
FIXES_COUNT="$(printf "%s\n"    "$ANALYSIS_OUT" | awk -F= '/^FIXES_COUNT=/{print $2; exit}')"

FEATURES_COUNT="${FEATURES_COUNT:-0}"
FIXES_COUNT="${FIXES_COUNT:-0}"
case "$FEATURES_COUNT" in ''|*[!0-9]* ) FEATURES_COUNT=0 ;; esac
case "$FIXES_COUNT"    in ''|*[!0-9]* ) FIXES_COUNT=0    ;; esac

if [ "$FEATURES_COUNT" -eq 0 ] && [ "$FIXES_COUNT" -eq 0 ]; then
  echo "Nothing to release: both '## Features' and '## Fixes' are empty in the in-progress section." >&2
  exit 3
fi

# --------------------------------------------------------------------
# Compute/override NEW_VERSION
# --------------------------------------------------------------------
validate_semver() {
  case "$1" in
    [0-9]*.[0-9]*.[0-9]*) return 0 ;;
    *) return 1 ;;
  esac
}

semver_gt() { # returns 0 (true) if $1 > $2
  a1=$(printf "%s" "$1" | cut -d. -f1); a2=$(printf "%s" "$1" | cut -d. -f2); a3=$(printf "%s" "$1" | cut -d. -f3)
  b1=$(printf "%s" "$2" | cut -d. -f1); b2=$(printf "%s" "$2" | cut -d. -f2); b3=$(printf "%s" "$2" | cut -d. -f3)
  if [ "$a1" -gt "$b1" ]; then return 0; fi
  if [ "$a1" -lt "$b1" ]; then return 1; fi
  if [ "$a2" -gt "$b2" ]; then return 0; fi
  if [ "$a2" -lt "$b2" ]; then return 1; fi
  [ "$a3" -gt "$b3" ]
}

if [ -n "$VERSION_OVERRIDE" ]; then
  if ! validate_semver "$VERSION_OVERRIDE"; then
    echo "--version must be in x.y.z form (digits and dots only)" >&2
    exit 2
  fi
  if ! semver_gt "$VERSION_OVERRIDE" "$CURRENT_VERSION"; then
    echo "Provided --version ($VERSION_OVERRIDE) must be greater than current ($CURRENT_VERSION)" >&2
    exit 2
  fi
  NEW_VERSION="$VERSION_OVERRIDE"
  BUMP_KIND="override"
else
  if [ "$FEATURES_COUNT" -gt 0 ]; then
    BUMP_KIND="minor"
    Y=$((Y + 1)); Z=0
  else
    BUMP_KIND="patch"
    Z=$((Z + 1))
  fi
  NEW_VERSION="${X}.${Y}.${Z}"
fi

echo "Bump: $BUMP_KIND"
echo "Current version: $CURRENT_VERSION  ->  New version: $NEW_VERSION"
echo "Release date: $RELEASE_DATE"

# Guard: do not duplicate release header (check by version only) — fixed-string to avoid regex pitfalls
if grep -Fq "# v${NEW_VERSION} (" "$CHANGELOG_FILE"; then
  echo "CHANGELOG already contains a release header for version v${NEW_VERSION}" >&2
  exit 1
fi

# --------------------------------------------------------------------
# DRY RUN MODE: stop here before changing anything
# --------------------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
  echo "----- DRY RUN -----"
  echo "Bump kind: $BUMP_KIND"
  echo "Current version: $CURRENT_VERSION"
  echo "New version: $NEW_VERSION"
  echo "Release date: $RELEASE_DATE"
  echo "CHANGELOG features count: $FEATURES_COUNT"
  echo "CHANGELOG fixes count: $FIXES_COUNT"
  echo
  echo "Files that WOULD be modified:"
  echo " - $CITATION_FILE"
  echo " - $CARGO_FILE"
  echo " - $CHANGELOG_FILE"
  if [ -f "$README_FILE" ]; then
    echo " - $README_FILE"
  else
    echo " - (no README.md present)"
  fi
  echo " - $LICENSE_FILE"
  echo " - Cargo.lock (via cargo generate-lockfile)"
  echo
  echo "Commands that WOULD run:"
  echo " - cargo generate-lockfile"
  echo
  echo "No files were changed."
  exit 0
fi

# --------------------------------------------------------------------
# Backups
# --------------------------------------------------------------------
cp "$CITATION_FILE"  "${CITATION_FILE}.bak.$(ts)"
cp "$CARGO_FILE"     "${CARGO_FILE}.bak.$(ts)"
cp "$CHANGELOG_FILE" "${CHANGELOG_FILE}.bak.$(ts)"
if [ -f "$README_FILE" ]; then
  cp "$README_FILE" "${README_FILE}.bak.$(ts)"
fi
cp "$LICENSE_FILE" "${LICENSE_FILE}.bak.$(ts)"

# --------------------------------------------------------------------
# Update CITATION.cff: version and date-released
# --------------------------------------------------------------------
awk -v newv="$NEW_VERSION" -v rdate="$RELEASE_DATE" '
BEGIN { ver_seen=0; date_seen=0 }
{
  if ($0 ~ /^version:[[:space:]]*"/)       { print "version: \"v" newv "\""; ver_seen=1; next }
  if ($0 ~ /^date-released:[[:space:]]*"/) { print "date-released: \"" rdate "\""; date_seen=1; next }
  print
}
END {
  if (ver_seen==0)  print "version: \"v" newv "\""
  if (date_seen==0) print "date-released: \"" rdate "\""
}
' "$CITATION_FILE" > "${CITATION_FILE}.tmp"
mv "${CITATION_FILE}.tmp" "$CITATION_FILE"

# --------------------------------------------------------------------
# Update Cargo.toml [package] version
# --------------------------------------------------------------------
awk -v newv="$NEW_VERSION" '
BEGIN { inpkg=0; done=0 }
{
  if ($0 ~ /^\[package\][[:space:]]*$/) { inpkg=1; print; next }
  if ($0 ~ /^\[/ && inpkg==1) { inpkg=0 }
  if (inpkg==1 && $0 ~ /^[[:space:]]*version[[:space:]]*=/) {
    sub(/=[[:space:]]*".*"/, "= \"" newv "\""); print; done=1; next
  }
  print
}
END { if (done==0) { print "##AWK_NO_PACKAGE_VERSION_FOUND##" > "/dev/stderr" } }
' "$CARGO_FILE" > "${CARGO_FILE}.tmp" 2> "${CARGO_FILE}.awk.err" || true

if grep -q '##AWK_NO_PACKAGE_VERSION_FOUND##' "${CARGO_FILE}.awk.err"; then
  rm -f "${CARGO_FILE}.tmp" "${CARGO_FILE}.awk.err"
  echo "Could not find 'version = \"...\"' inside [package] in $CARGO_FILE" >&2
  exit 1
fi
rm -f "${CARGO_FILE}.awk.err"
mv "${CARGO_FILE}.tmp" "$CARGO_FILE"

# --------------------------------------------------------------------
# Update CHANGELOG.md
# - Reset 'in progress' template
# - Insert '# v<NEW_VERSION> (<DATE>)' under it
# --------------------------------------------------------------------
awk -v newv="$NEW_VERSION" -v rdate="$RELEASE_DATE" '
BEGIN { did=0 }
{
  if (did==0 && $0 ~ /^# v1\.x \(in progress\)[[:space:]]*$/) {
    print "# v1.x (in progress)\n"
    print "## Highlights\n"
    print "## Features\n"
    print "## Fixes\n"
    print "# v" newv " (" rdate ")"
    did=1
    next
  }
  print
}
END {
  if (did==0) {
    print "##AWK_NO_INPROGRESS_HEADER##" > "/dev/stderr"
  }
}
' "$CHANGELOG_FILE" > "${CHANGELOG_FILE}.tmp" 2> "${CHANGELOG_FILE}.awk.err" || true

if grep -q '##AWK_NO_INPROGRESS_HEADER##' "${CHANGELOG_FILE}.awk.err"; then
  rm -f "${CHANGELOG_FILE}.tmp" "${CHANGELOG_FILE}.awk.err"
  echo "Could not find header '# v1.x (in progress)' in $CHANGELOG_FILE" >&2
  exit 1
fi
rm -f "${CHANGELOG_FILE}.awk.err"
mv "${CHANGELOG_FILE}.tmp" "$CHANGELOG_FILE"

# --------------------------------------------------------------------
# Update README.md (if present)
#   Replace the first line matching:
#     ^# WuppieFuzz v<semver>
#   with:
#     # WuppieFuzz v<NEW_VERSION>
# --------------------------------------------------------------------
if [ -f "$README_FILE" ]; then
  awk -v newv="$NEW_VERSION" '
  BEGIN { done=0 }
  {
    if (!done && $0 ~ /^# WuppieFuzz v[0-9]+\.[0-9]+\.[0-9]+([[:space:]]*)$/) {
      print "# WuppieFuzz v" newv
      done=1
      next
    }
    print
  }
  END {
    if (done==0) {
      # Signal to stderr so the shell can fail: header not found to update
      print "##AWK_NO_README_HEADER_FOUND##" > "/dev/stderr"
    }
  }
  ' "$README_FILE" > "${README_FILE}.tmp" 2> "${README_FILE}.awk.err" || true

  if grep -q '##AWK_NO_README_HEADER_FOUND##' "${README_FILE}.awk.err"; then
    rm -f "${README_FILE}.tmp" "${README_FILE}.awk.err"
    echo "README.md: did not find a line like '# WuppieFuzz v<semver>' to update" >&2
    exit 1
  fi
  rm -f "${README_FILE}.awk.err"
  mv "${README_FILE}.tmp" "$README_FILE"
fi

# --------------------------------------------------------------------
# Update LICENSE:
#   Ensure a '2021-<YYYY>' year range ends with the new release year.
#   We update any '2021-####' match to '2021-<RELEASE_YEAR>'.
# --------------------------------------------------------------------
# Verify pattern exists first (to fail clearly if structure changes)
if ! grep -Eq '2021-[0-9][0-9][0-9][0-9]' "$LICENSE_FILE"; then
  echo "LICENSE: expected a '2021-YYYY' year range, but none found" >&2
  exit 1
fi

# Perform replacement (all occurrences of 2021-YYYY)
awk -v y="$RELEASE_YEAR" '
{ gsub(/2021-[0-9][0-9][0-9][0-9]/, "2021-" y); print }
' "$LICENSE_FILE" > "${LICENSE_FILE}.tmp"
mv "${LICENSE_FILE}.tmp" "$LICENSE_FILE"

# Post-verify LICENSE now contains the intended year
grep -Fq "2021-${RELEASE_YEAR}" "$LICENSE_FILE" \
  || { echo "LICENSE: did not update to '2021-${RELEASE_YEAR}' as expected" >&2; exit 1; }

# --------------------------------------------------------------------
# Post-change sanity checks
# --------------------------------------------------------------------
grep -q "^version:[[:space:]]*\"v${NEW_VERSION}\"" "$CITATION_FILE" \
  || { echo "CITATION.cff: version not set to v${NEW_VERSION}" >&2; exit 1; }
grep -q "^date-released:[[:space:]]*\"${RELEASE_DATE}\"" "$CITATION_FILE" \
  || { echo "CITATION.cff: date-released not set to ${RELEASE_DATE}" >&2; exit 1; }

grep -A5 "^\[package\]" "$CARGO_FILE" \
  | grep -q "^[[:space:]]*version[[:space:]]*=[[:space:]]*\"${NEW_VERSION}\"" \
  || { echo "Cargo.toml: [package] version not set to ${NEW_VERSION}" >&2; exit 1; }

# Fixed-string check to avoid regex pitfalls
grep -Fq "# v${NEW_VERSION} (" "$CHANGELOG_FILE" \
  || { echo "CHANGELOG.md: missing release header for v${NEW_VERSION}" >&2; exit 1; }

if [ -f "$README_FILE" ]; then
  grep -Fq "# WuppieFuzz v${NEW_VERSION}" "$README_FILE" \
    || { echo "README.md: header not updated to '# WuppieFuzz v${NEW_VERSION}'" >&2; exit 1; }
fi

# Ensure LICENSE has final year = RELEASE_YEAR
grep -Fq "2021-${RELEASE_YEAR}" "$LICENSE_FILE" \
  || { echo "LICENSE: final year is not '${RELEASE_YEAR}'" >&2; exit 1; }

# --------------------------------------------------------------------
# Generate or refresh Cargo.lock
# --------------------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in PATH; cannot generate lockfile" >&2
  exit 1
fi

echo "Regenerating Cargo.lock with 'cargo generate-lockfile' ..."
if ! cargo generate-lockfile; then
  echo "cargo generate-lockfile failed" >&2
  exit 1
fi

printf '✅ Release prepared.\n- Bump: %s\n- Version: %s → %s\n- Date: %s\n- Files updated: CITATION.cff, Cargo.toml, CHANGELOG.md%s, %s, Cargo.lock\n' \
  "$BUMP_KIND" "$CURRENT_VERSION" "$NEW_VERSION" "$RELEASE_DATE" \
  "$( [ -f "$README_FILE" ] && printf ", README.md" || printf "" )" \
  "$LICENSE_FILE"
``