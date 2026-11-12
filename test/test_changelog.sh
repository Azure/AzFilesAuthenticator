#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -f "$TMP/CHANGELOG.md" "$TMP/rpm.spec" "$TMP/update-changelog.sh" "$TMP/update-version.sh" "$TMP/configure.ac" "$TMP/expected-rpm" "$TMP/expected-debian" "$TMP/error" "$TMP/debian/changelog" "$TMP/debian/control"; rmdir "$TMP/debian" "$TMP"' EXIT

mkdir "$TMP/debian"
cp "$REPO_ROOT/update-changelog.sh" "$REPO_ROOT/update-version.sh" "$REPO_ROOT/rpm.spec" "$REPO_ROOT/configure.ac" "$TMP/"
cp "$REPO_ROOT/debian/control" "$TMP/debian/"
cd "$TMP"

cat > CHANGELOG.md <<'EOF'
# Changelog

## [Unreleased]

- Do not publish this note yet.

## [1.0-13] - 2026-11-12

### Fixed

- Preserve 100% of notes, including literal %{name} macros.
- Preserve punctuation: quotes, backslashes \ and $(shell text).

## [1.0-1] - 2025-02-20

- Initial release.
EOF

bash ./update-changelog.sh --write
bash ./update-changelog.sh --check
grep -Fq -- '- Fixed: Preserve 100%% of notes, including literal %%{name} macros.' rpm.spec
grep -Fq -- '  * Fixed: Preserve 100% of notes, including literal %{name} macros.' debian/changelog
grep -Fq -- '$(shell text).' debian/changelog
if command -v rpmspec >/dev/null 2>&1; then
    rpm_notes=$(rpmspec -q --qf '%{CHANGELOGTEXT}\n' rpm.spec)
    grep -Fq -- '- Fixed: Preserve 100% of notes, including literal %{name} macros.' <<< "$rpm_notes"
else
    echo "SKIP: RPM macro round-trip query requires rpmspec."
fi
if grep -Fq 'Do not publish' rpm.spec debian/changelog; then
    echo "FAIL: Unreleased notes leaked into package metadata." >&2
    exit 1
fi

cp rpm.spec expected-rpm
cp debian/changelog expected-debian
bash ./update-changelog.sh --write
cmp rpm.spec expected-rpm
cmp debian/changelog expected-debian
echo "PASS: Generation preserves notes and history, excludes Unreleased, and is idempotent."

printf '\n' >> debian/changelog
if bash ./update-changelog.sh --check > error 2>&1; then
    echo "FAIL: Stale package changelog passed verification." >&2
    exit 1
fi
grep -Fq 'Package changelogs are stale' error
cp expected-debian debian/changelog

# Failed validation must not overwrite either generated file.
for invalid in date empty duplicate unsupported tabs missing mismatch order; do
    case "$invalid" in
        date) sed -i 's/2026-11-12/2026-02-30/' CHANGELOG.md ;;
        empty) printf '\n## [1.0-0] - 2025-01-01\n' >> CHANGELOG.md ;;
        duplicate) printf '\n## [1.0-1] - 2025-02-20\n\n- Duplicate.\n' >> CHANGELOG.md ;;
        unsupported) printf '\nUnstructured release prose.\n' >> CHANGELOG.md ;;
        tabs) printf '\n- Truncated\tnote.\n' >> CHANGELOG.md ;;
        missing) printf '# No releases\n' > CHANGELOG.md ;;
        mismatch) printf '## [1.0-14] - 2026-11-12\n\n- Next release.\n' > CHANGELOG.md ;;
        order) printf '## [1.0-13] - 2026-11-12\n\n- Current.\n\n## [1.0-1] - 2026-11-13\n\n- Out of order.\n' > CHANGELOG.md ;;
    esac
    if bash ./update-changelog.sh --write > error 2>&1; then
        echo "FAIL: Invalid changelog accepted: $invalid." >&2
        exit 1
    fi
    grep -q 'ERROR:' error
    cmp rpm.spec expected-rpm
    cmp debian/changelog expected-debian
    # Reset to a valid source for the next case.
    printf '## [1.0-13] - 2026-11-12\n\n- Current.\n\n## [1.0-1] - 2025-02-20\n\n- Initial release.\n' > CHANGELOG.md
done
echo "PASS: Drift and invalid input are rejected without overwriting package history."

if bash ./update-version.sh 1.0 14 > error 2>&1; then
    echo "FAIL: Version bump without matching release notes succeeded." >&2
    exit 1
fi
cmp rpm.spec expected-rpm
cmp debian/changelog expected-debian
printf '## [1.0-14] - 2026-11-13\n\n- Next release.\n\n## [1.0-13] - 2026-11-12\n\n- Previous release.\n' > CHANGELOG.md
bash ./update-version.sh 1.0 14
bash ./update-changelog.sh --check
grep -q '^Version: *1.0$' rpm.spec
grep -q '^Release: *14%{?dist}$' rpm.spec
grep -q '^azfilesauth (1.0-14)' debian/changelog
grep -q '^azfilesauth (1.0-13)' debian/changelog
grep -Fq 'AC_INIT([azfilesauth],[1.0.14],' configure.ac
echo "PASS: Version bumps require matching notes and preserve previous releases."
