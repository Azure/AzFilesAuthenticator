#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export TZ=UTC

cd "$(dirname "$0")"
MODE="${1:---write}"
if [[ $# -gt 2 || ( "$MODE" != "--write" && "$MODE" != "--check" ) ||
      ( "$MODE" == "--check" && $# -gt 1 ) ]]; then
    echo "Usage: $0 [--write [expected-version] | --check]" >&2
    exit 1
fi

EXPECTED_VERSION="${2:-$(awk '/^Version:/ {v=$2} /^Release:/ {sub(/%.*/, "", $2); r=$2} END {print v "-" r}' rpm.spec)}"
MAINTAINER=$(sed -n 's/^Maintainer: //p' debian/control)
if [[ -z "$MAINTAINER" ]]; then
    echo "ERROR: debian/control must specify a Maintainer." >&2
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -f "$TMP/entries" "$TMP/rpm" "$TMP/debian" "$TMP/spec"; rmdir "$TMP"' EXIT

# Accept a deliberately small Markdown subset so no release notes are silently lost.
awk '
    function fail(message) {
        print "ERROR: CHANGELOG.md:" NR ": " message > "/dev/stderr"
        exit 1
    }
    /^## / {
        if (released && !notes) fail("release must contain at least one bullet")
        released = 0
        notes = 0
        category = ""
        if ($0 == "## [Unreleased]") { seen_heading = 1; next }
        if ($0 !~ /^## \[[0-9]+\.[0-9]+-[0-9]+\] - [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/)
            fail("expected ## [major.minor-release] - YYYY-MM-DD")
        version = $2
        gsub(/[][]/, "", version)
        if (seen[version]++) fail("duplicate release " version)
        print "H\t" version "\t" $4
        released = 1
        seen_heading = 1
        next
    }
    !seen_heading || !released || /^[[:space:]]*$/ { next }
    /\t/ { fail("tabs are not supported in release notes") }
    /^### [A-Za-z][A-Za-z ]*$/ { category = substr($0, 5); next }
    /^- [^[:space:]]/ {
        text = substr($0, 3)
        if (category != "") text = category ": " text
        print "N\t" text
        notes++
        next
    }
    { fail("use ### Category headings and single-line - bullets in releases") }
    END {
        if (released && !notes) {
            print "ERROR: release must contain at least one bullet" > "/dev/stderr"
            exit 1
        }
    }
' CHANGELOG.md > "$TMP/entries"

: > "$TMP/rpm"
: > "$TMP/debian"
LATEST=""
PREVIOUS_DATE=""
while IFS=$'\t' read -r KIND VALUE RELEASE_DATE; do
    if [[ "$KIND" == "H" ]]; then
        if ! NORMALIZED_DATE=$(date -d "$RELEASE_DATE" +%F) || [[ "$NORMALIZED_DATE" != "$RELEASE_DATE" ]]; then
            echo "ERROR: Invalid release date: $RELEASE_DATE" >&2
            exit 1
        fi
        if [[ -n "$PREVIOUS_DATE" && "$RELEASE_DATE" > "$PREVIOUS_DATE" ]]; then
            echo "ERROR: Releases must be ordered newest date first." >&2
            exit 1
        fi
        PREVIOUS_DATE="$RELEASE_DATE"
        if [[ -z "$LATEST" ]]; then
            LATEST="$VALUE"
            if [[ "$LATEST" != "$EXPECTED_VERSION" ]]; then
                echo "ERROR: Latest changelog release $LATEST does not match package version $EXPECTED_VERSION." >&2
                exit 1
            fi
        else
            printf '\n -- %s  %s\n\n' "$MAINTAINER" "$DEB_DATE" >> "$TMP/debian"
            printf '\n' >> "$TMP/rpm"
        fi
        DEB_DATE=$(date -d "$RELEASE_DATE" -R)
        printf '* %s %s - %s\n' "$(date -d "$RELEASE_DATE" '+%a %b %d %Y')" "$MAINTAINER" "$VALUE" >> "$TMP/rpm"
        printf 'azfilesauth (%s) unstable; urgency=medium\n\n' "$VALUE" >> "$TMP/debian"
    else
        # RPM expands macros even in changelog text.
        printf -- '- %s\n' "${VALUE//%/%%}" >> "$TMP/rpm"
        printf '  * %s\n' "$VALUE" >> "$TMP/debian"
    fi
done < "$TMP/entries"
if [[ -z "$LATEST" ]]; then
    echo "ERROR: CHANGELOG.md must contain a released version." >&2
    exit 1
fi
printf '\n -- %s  %s\n' "$MAINTAINER" "$DEB_DATE" >> "$TMP/debian"

if ! grep -qx '%changelog' rpm.spec; then
    echo "ERROR: rpm.spec must contain a %changelog section." >&2
    exit 1
fi
awk '/^%changelog$/ {exit} {print}' rpm.spec > "$TMP/spec"
printf '%%changelog\n' >> "$TMP/spec"
cat "$TMP/rpm" >> "$TMP/spec"

if [[ "$MODE" == "--check" ]]; then
    if ! cmp -s "$TMP/spec" rpm.spec || ! cmp -s "$TMP/debian" debian/changelog; then
        echo "ERROR: Package changelogs are stale. Run bash ./update-changelog.sh --write." >&2
        exit 1
    fi
    echo "Package changelogs match CHANGELOG.md ($LATEST)."
else
    cp "$TMP/spec" rpm.spec
    cp "$TMP/debian" debian/changelog
    echo "Generated RPM and Debian changelogs for $LATEST."
fi
