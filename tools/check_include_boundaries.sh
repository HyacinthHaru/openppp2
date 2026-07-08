#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
violations=0

# client must not include server headers
if rg -n '#include <ppp/app/server/' ppp/app/client/ -g'*.{h,cpp}' 2>/dev/null; then
  echo "FAIL: client includes server headers"
  violations=$((violations + 1))
fi

# facade/views must not pull heavy deps (skip if directory missing)
if [[ -d ppp/facade/views ]]; then
  if rg -n 'configurations/AppConfiguration|json/json' ppp/facade/views/ -g'*.h' 2>/dev/null; then
    echo "FAIL: facade views pull heavy deps"
    violations=$((violations + 1))
  fi
fi

if [[ $violations -eq 0 ]]; then
  echo "PASS: include boundaries"
else
  exit 1
fi
