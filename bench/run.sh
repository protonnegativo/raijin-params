#!/usr/bin/env bash
# Reproducible token benchmark: arjun output vs raijin-params output on the same parameter discovery.
#
# usage: bench/run.sh [workdir]
#        LIVE=1 bench/run.sh [workdir]   start the local lab, run arjun again and refresh bench/fixtures first
# needs: go, python3 with tiktoken (pip install tiktoken); LIVE=1 also needs arjun
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>, ARJUN=<path>
#
# Safety: LIVE=1 tests only the lab it starts itself (bench/lab.py) on 127.0.0.1, ports 19150 and 19151,
# with arjun's small wordlist, 2 threads and at most 50 requests per second. It stops the lab when it
# exits. A live run takes about two minutes.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
ARJUN=${ARJUN:-arjun}
mkdir -p "$W"
echo "workdir: $W"

# Lab: one python process with two sites (see lab.py).
# noisy:    a catalog: 30 product pages with page, currency and format, 15 articles with page and print,
#           and a search page with q, sort and page.
# findings: a small app: url and callback on /fetch and /preview, next on /login and /logout, file,
#           template, cmd and host, debug and admin, id on two API routes, user_id, and a POST login form
#           with username and password, plus a few plain parameters.
declare -A port=([noisy]=19150 [findings]=19151)
declare -A methods=([noisy]=GET [findings]=GET,POST)
printf '127.0.0.1\n' > "$W/scope.txt"

targets() {
  local p=$1
  if [ "$p" = "${port[noisy]}" ]; then
    for n in $(seq 1 30); do echo "http://127.0.0.1:$p/product/$n"; done
    for n in $(seq 1 15); do echo "http://127.0.0.1:$p/article/$n"; done
    echo "http://127.0.0.1:$p/search"
  else
    for r in fetch preview login logout download render tools/ping api/user api/order account admin report about; do
      echo "http://127.0.0.1:$p/$r"
    done
  fi
}

(cd "$ROOT" && go build -o "$W/raijin-params" ./cmd/raijin-params)

if [ "${LIVE:-}" = 1 ]; then
  for p in "${port[@]}"; do
    if ss -ltn | grep -q ":$p "; then echo "port $p is busy; free it first" >&2; exit 1; fi
  done
  python3 "$HERE/lab.py" "${port[noisy]}=shop" "${port[findings]}=app" > "$W/lab.log" 2>&1 &
  echo $! > "$W/pids"
  trap '[ -f "$W/pids" ] && xargs kill < "$W/pids" 2>/dev/null || true' EXIT
  sleep 1
  for name in noisy findings; do
    f=$HERE/fixtures/$name
    mkdir -p "$f"
    targets "${port[$name]}" > "$f/targets.txt"
    opts=(-w small -t 2 --rate-limit 50)
    # raijin-params runs arjun (-i targets -oJ <tmp> -q -m <method>, once per method) and saves the
    # exports, one after the other, as raw: that file is the fixture.
    "$W/raijin-params" --arjun "$ARJUN" --scope "$W/scope.txt" -l "$f/targets.txt" --method "${methods[$name]}" \
      --wordlist small --threads 2 --rate 50 --raw "$f/raw.json" > "$W/$name.live.json"
    # arjun as an agent would run it, with the same options: its default text output (progress and
    # results on stdout) and its -oT text export, from a separate run per method.
    : > "$f/text.txt"; : > "$f/text_ot.txt"
    for m in ${methods[$name]//,/ }; do
      "$ARJUN" -i "$f/targets.txt" -m "$m" "${opts[@]}" -oT "$f/text_ot.txt" < /dev/null >> "$f/text.txt" 2>&1
    done
  done
fi

scenario() {
  local name=$1
  local f=$HERE/fixtures/$name o=$W/$name
  mkdir -p "$o"
  # The same exports without the request headers (arjun writes all 6 of its default headers for every
  # URL) and without indentation: the smallest JSON an agent could get from arjun with jq.
  python3 -c 'import json,sys
text, dec, i = open(sys.argv[1]).read(), json.JSONDecoder(), 0
while True:
    while i < len(text) and text[i].isspace():
        i += 1
    if i >= len(text):
        break
    obj, i = dec.raw_decode(text, i)
    print(json.dumps({u: {"method": r["method"], "params": r["params"]} for u, r in obj.items()}, separators=(",", ":")))' "$f/raw.json" > "$o/lean.json"
  # raijin-params replays raw with --input, so every row sees the same results.
  (cd "$ROOT" && "$W/raijin-params" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.json") > "$o/raijin.json"
  (cd "$ROOT" && "$W/raijin-params" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.json" --pretty) > "$o/raijin_pretty.json"
  (cd "$ROOT" && "$W/raijin-params" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.json" --format table) > "$o/raijin_table.txt"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  python3 "$HERE/verify.py" "$f/raw.json" "$o/raijin.json"
  echo "separate arjun text runs: $(grep -c 'Parameters found' "$f/text.txt") URLs with parameters on stdout, $(wc -l < "$f/text_ot.txt") lines in -oT"
  "$PY" "$HERE/count_tokens.py" \
    "arjun -oJ (raijin-params' raw)=$f/raw.json" \
    "arjun -oJ, no headers, compact=$o/lean.json" \
    "arjun text (stdout+stderr)=$f/text.txt" \
    "arjun -oT=$f/text_ot.txt" \
    "raijin-params JSON (default)=$o/raijin.json" \
    "raijin-params --pretty=$o/raijin_pretty.json" \
    "raijin-params --format table=$o/raijin_table.txt"
}

scenario noisy
scenario findings
