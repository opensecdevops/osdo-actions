#!/usr/bin/env bash
# Sets python-cache, node-cache and go-cache to true or false in $GITHUB_OUTPUT,
# depending on whether the dependency files that the setup-* caches key on exist.
# Run from the repository root. Directories .git and node_modules are ignored.
set -euo pipefail

found() {
  [ -n "$(find . \( -path ./.git -o -path ./node_modules \) -prune -o -name "$1" -print -quit)" ]
}

python_cache=false
if found requirements.txt || found pyproject.toml; then python_cache=true; fi

node_cache=false
if found package-lock.json; then node_cache=true; fi

go_cache=false
if found go.sum; then go_cache=true; fi

{
  echo "python-cache=$python_cache"
  echo "node-cache=$node_cache"
  echo "go-cache=$go_cache"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
