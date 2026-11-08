#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Downloads the captures listed in testdata/captures/CACHED (the full
# recordings of the UOWM dataset, 29 to 75 MB each, not committed) into the
# capture cache (IEC104_CAPTURE_CACHE, default testdata/captures/cache,
# git-ignored) under their clean names and verifies every SHA256. Files already cached with the right hash are not
# downloaded again. The committed captures are checked with
# `shasum -a 256 -c SHA256SUMS` in testdata/captures.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
list="$root/testdata/captures/CACHED"
cache="${IEC104_CAPTURE_CACHE:-$root/testdata/captures/cache}"

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

fetched=0 total=0
while IFS=$'\t' read -r rel want url; do
	[ -n "$rel" ] || continue
	total=$((total + 1))
	dst="$cache/$rel"
	if [ -f "$dst" ] && [ "$(sha "$dst")" = "$want" ]; then
		continue
	fi
	mkdir -p "$(dirname "$dst")"
	curl -fsSL --retry 3 -o "$dst.part" "$url"
	got=$(sha "$dst.part")
	if [ "$got" != "$want" ]; then
		rm -f "$dst.part"
		echo "$rel: SHA256 $got, expected $want ($url)" >&2
		exit 1
	fi
	mv "$dst.part" "$dst"
	fetched=$((fetched + 1))
done <"$list"
echo "captures: $fetched downloaded, all $total verified in $cache"
