#!/bin/sh
set -e
cd "$(dirname "$0")"
for f in cve-*.c; do gcc -c "$f" -o /dev/null; done
