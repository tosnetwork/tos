#!/usr/bin/env bash
# Build the public overview without leaving LaTeX intermediates in doc/.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
command -v pdflatex >/dev/null || { echo 'pdflatex is required' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct -- doc/pq.tex)}"
# An untracked initial source has no commit timestamp yet.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1790899200}"
for pass in 1 2 3; do
    if ! pdflatex -interaction=nonstopmode -halt-on-error -no-shell-escape \
        -output-directory "$work" "$repo/doc/pq.tex" > "$work/build.log" 2>&1; then
        cat "$work/build.log" >&2
        exit 1
    fi
done
if grep -Eq 'Overfull \\hbox|Overfull \\vbox|undefined references' "$work/pq.log"; then
    grep -E 'Overfull|undefined references' "$work/pq.log" >&2
    exit 1
fi
cp "$work/pq.pdf" "$repo/doc/pq.pdf"
echo 'Built doc/pq.pdf'
