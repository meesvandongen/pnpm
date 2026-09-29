#!/usr/bin/env bash
# Runs real build tools as tracked pipeline tasks: esbuild, a Go program,
# and oxlint, a Rust one. Each second run must be restored from the cache,
# and a change to a source file must make both tasks run again.
set -euo pipefail

pnpm_bin="$1"
work="${RUNNER_TEMP:-/tmp}/fs-access-real-tools"
# Outside the workspace, whose root the tasks list.
output="$work.output"
rm -rf "$work"
mkdir -p "$work/app/src"
cd "$work"
export XDG_CACHE_HOME="$work.cache"
rm -rf "$XDG_CACHE_HOME"

git init -q
git config user.email ci@example.com
git config user.name ci
printf 'node_modules/\ndist/\n' > .gitignore
echo '{"name":"root","private":true}' > package.json
cat > pnpm-workspace.yaml <<'YAML'
packages: [app]
allowBuilds:
  esbuild: true
pipelines:
  default: [bundle, lint]
tasks:
  bundle:
    inputs: [{ auto: true }]
    outputs: [{ auto: true }]
  lint:
    # oxlint lists the project directory, where bundle creates dist: run
    # side by side, lint's first run would not be cached.
    dependsOn: [bundle]
    inputs: [{ auto: true }]
    # A task is cached only when it declares its outputs.
    outputs: []
YAML
cat > app/package.json <<'JSON'
{
  "name": "app",
  "version": "1.0.0",
  "scripts": {
    "bundle": "esbuild src/index.js --bundle --outfile=dist/out.js",
    "lint": "oxlint src"
  },
  "devDependencies": { "esbuild": "^0.25.0", "oxlint": "^1.0.0" }
}
JSON
echo 'export const answer = 42;' > app/src/answer.js
echo "import { answer } from './answer.js'; console.log(answer);" > app/src/index.js
git add -A
git commit -qm init
"$pnpm_bin" install

# Run the pipeline and print the tasks restored from the cache, sorted.
restored() {
  "$pnpm_bin" pipeline --full > "$output" 2>&1 || { cat "$output"; exit 1; }
  cat "$output" >&2
  if grep -q 'not every file access' "$output"; then
    echo "a task was not fully observed" >&2
    exit 1
  fi
  local report
  report=$(sed -n 's/^Report: //p' "$output")
  node -e '
    const events = require("fs").readFileSync(process.argv[1], "utf8").trim().split("\n").map(JSON.parse);
    console.log(events.filter((e) => e.event === "taskFinished" && e.cache === "hit").map((e) => e.task).sort().join(" "));
  ' "$report/events.ndjson"
}

expect() {
  local actual
  actual=$(restored)
  if [ "$actual" != "$1" ]; then
    echo "expected restored tasks '$1', got '$actual'" >&2
    exit 1
  fi
  echo "restored: '$actual'"
}

expect ''
expect 'app#bundle app#lint'
echo 'export const answer = 43;' > app/src/answer.js
expect ''
expect 'app#bundle app#lint'
grep -q 43 app/dist/out.js
