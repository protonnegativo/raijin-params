# ⚡ Raijin Params

**arjun for AI agents: every hidden parameter that changes the response, the same parameter set across many URLs collapsed into one entry, the ones that smell like SSRF, file read, redirects, command injection, debug or IDOR ranked first.**

`raijin-params` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It runs [arjun](https://github.com/s0md3v/Arjun) underneath and returns the **Raijin Schema**: one compact JSON where every URL, method and parameter arjun found is listed, URLs with exactly the same parameters share one entry, parameters whose names suggest an attack class (`url`, `next`, `file`, `cmd`, `debug`, `admin`, `id`, `sort`...) are ranked findings, plain ones (`page`, `lang`, `tab`) are groups, and anything it had to cut is counted.

## Why not just run arjun?

arjun is built for people. An agent pays for every byte it reads. Its default output is a progress log: a banner, a few lines per URL and a `Processing chunks: 3/4` line, with colors, for every chunk it sends. Its JSON export (`-oJ`) is indented and repeats the 6 request headers arjun sent for every URL. Its text export (`-oT`) is one URL per line with made-up values, and none of them say which parameter is worth testing first.

Here is the same run, with the same results, read by an agent (tokens, `o200k_base`):

```
Noisy run: 46 URLs, 123 parameters, 1 finding
  raijin-params  ▏                          185 tokens
  arjun -oT      ▋                        1,302 tokens
  arjun -oJ      ███▉                     7,530 tokens
  arjun text     ████████████████████    38,814 tokens

Findings run: 13 URLs, 22 parameters, 12 findings (5 high, 6 medium, 1 low)
  raijin-params  █▎                         574 tokens
  arjun -oT      ▊                          312 tokens
  arjun -oJ      ████▉                    2,213 tokens
  arjun text     ████████████████████     9,055 tokens
```

raijin-params reads **41×** fewer tokens than `arjun -oJ` on the noisy run and **3.9×** fewer on the findings run, and **210×** and **16×** fewer than arjun's default text output. Each run's bars are drawn to scale against arjun's text output.

- **Nothing is lost.** Every URL, method and parameter arjun reported is in the output, with the headers arjun sent when they are not its defaults. `bench/verify.py` checked all 145 results of both runs and none were missing.
- **Same parameters, one entry.** 30 product pages that all take `page`, `currency` and `format` are one group with one location, `/product/[1-30]`. `/fetch` and `/preview`, which both take `url` and `callback`, are one finding.
- **The real targets come first.** `cmd`, `url`, `host`, `file` and `template` are high, `next`, `admin`, `debug`, `id` and `user_id` are medium, `sort` and `q` are low. Plain parameters are groups.
- **Output is bounded.** On a huge run, `--max-bytes` cuts the least important data first and counts every cut. arjun's output grows with every URL.
- **Details are one file away.** arjun's JSON exports are saved to disk, and their path is in `raw`. They replay with `--input`.

Against `arjun -oT`, raijin-params is **7×** smaller on the noisy run and **1.8× larger** on the findings run. When every URL has its own parameters there is little to collapse, and the ids, severities and classes cost more than a bare URL list. `-oT` also gives no ranking, writes made-up values into every URL (`/fetch?callback=8551&url=1746`), and gives a POST result as a URL and a tab. Stripping arjun's JSON of its headers and indentation with `jq` gives about the same size as `-oT` (1,303 and 347 tokens). Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-params/cmd/raijin-params@latest
```

You also need [arjun](https://github.com/s0md3v/Arjun) on `PATH` (`pipx install arjun`), or pass `--arjun <path>`. raijin-params was built against arjun 2.2.7. x8 is not supported yet.

## Usage

```bash
raijin-params --scope scope.txt                                # test every host the scope names
raijin-params --scope scope.txt -u https://app.example.com/search
raijin-params --scope scope.txt -l urls.txt --method GET,POST --wordlist medium --rate 20
raijin-params --scope scope.txt --input arjun.json               # reduce output you already have (-oJ)
raijin-params --scope scope.txt -l urls.txt --state run.json     # mark findings that are new since last run
raijin-params ... -- --headers 'Cookie: session=...' --stable    # anything after -- goes to arjun
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!admin.example.com
```

With no `-u`, `-l` or `--input`, raijin-params tests what the scope names: every domain, every IP, and every address of ranges up to a /24, minus exclusions, each as `https://<host>/` (arjun skips a URL that does not start with `http`, and falls back to `http://` when `https://` fails). A wildcard names no host and a larger range is too big to sweep blindly, so for each one `next` gives the command that enumerates it first (`raijin-subs` or `raijin-ports`); `next` also suggests `raijin-crawl` to find more endpoints with parameters than the root URLs.

Targets outside the scope are dropped before arjun runs, and results for out-of-scope URLs are dropped from the output. Both are counted in `omitted.out_of_scope`. A target without a scheme gets `http://`, because arjun skips it otherwise.

raijin-params runs arjun once per method in `--method` (`GET` by default; `POST`, `JSON` and `XML` are arjun's body methods; `XML` needs `-- --include '<root>$arjun$</root>'`), with `-i <targets> -oJ <file> -q`. arjun's own default wordlist is `large` (about 26,000 names); `--wordlist small`, `medium` or a file changes it.

## Output

```json
{
  "tool": "raijin-params",
  "version": "0.1.0",
  "target": "13 target(s)",
  "summary": "13 URLs, 22 parameters (18 names): 12 findings (5 high, 6 medium, 1 low), 5 groups",
  "origin": "http://127.0.0.1:19151",
  "findings": [
    {"id": "rce-b84a0c71", "severity": "high", "tags": ["rce"], "params": ["cmd"], "locations": ["/tools/ping"]},
    {"id": "ssrf-028910a9", "severity": "high", "tags": ["ssrf"], "params": ["callback", "url"], "locations": ["/fetch", "/preview"]},
    {"id": "ssrf-ea8c109c", "severity": "high", "tags": ["ssrf"], "params": ["host"], "locations": ["/tools/ping"]},
    {"id": "file-a67355d4", "severity": "high", "tags": ["file"], "params": ["file"], "locations": ["/download"]},
    {"id": "redirect-8fb37aab", "severity": "medium", "tags": ["redirect"], "params": ["next"], "locations": ["/login", "/logout"]},
    {"id": "debug-d0e056d6", "severity": "medium", "tags": ["debug"], "params": ["debug"], "locations": ["/admin"]},
    {"id": "id-747985d4", "severity": "medium", "tags": ["id"], "params": ["id"], "locations": ["/api/order", "/api/user"]},
    {"id": "id-88022535", "severity": "medium", "tags": ["id"], "params": ["username"], "method": "POST", "locations": ["/login"]},
    {"id": "injection-1801356e", "severity": "low", "tags": ["injection"], "params": ["sort"], "locations": ["/report"]}
  ],
  "groups": [
    {"id": "params-87f7f9f5", "params": ["lang"], "locations": ["/render"]},
    {"id": "params-74892200", "params": ["password"], "method": "POST", "locations": ["/login"]}
  ],
  "raw": "bench/fixtures/findings/raw.json"
}
```

That is the real findings run from the benchmark, pretty-printed here with one entry per line. Two things are shortened: 3 of the 12 findings and 3 of the 5 groups are left out, and `raw` is relative to the repo. The tool writes it as one line. The noisy run's biggest entries:

```json
{"id":"params-ff023577","params":["currency","format","page"],"locations":["/product/[1-30]"]}
{"id":"params-19071a3e","params":["page","print"],"locations":["/article/[1-15]"]}
```

**Nothing arjun found is dropped silently.** Every URL, method and parameter is in exactly one finding or group. Only exact repeats collapse, and they are counted in `omitted.duplicates`.

What the reducer does:

- **One class per parameter.** Each parameter name is split into words (at `_`, `-`, `.`, `[`, and camelCase: `redirectUrl` is `redirect`, `url`), and takes the first class below that has one of its words, or all of its words joined, in its list. A name that ends in `id` after an object word (`userid`, `orderId`, `account_ids`) is `id`. A name with no class is plain.

  | Class | Severity | Names (and their words in longer names) |
  |---|---|---|
  | `rce` | high | `cmd`, `command`, `exec`, `execute`, `shell`, `eval`, `ping`, `system`, `sh`, `bash`, `powershell`, `cli`, `daemon` |
  | `redirect` | medium | `redirect`, `redir`, `return`, `returnTo`, `returnUrl`, `next`, `goto`, `continue`, `forward`, `dest`, `destination`, `out`, `back`, `success`, `failure`, `RelayState`... |
  | `ssrf` | high | `url`, `uri`, `link`, `href`, `src`, `host`, `domain`, `proxy`, `callback`, `webhook`, `feed`, `fetch`, `endpoint`, `server`, `site`, `remote`, `ip`, `port`, `target`, `wsdl` |
  | `file` | high | `file`, `filename`, `path`, `dir`, `folder`, `doc`, `document`, `include`, `require`, `template`, `tpl`, `layout`, `load`, `read`, `download`, `attachment`, `upload`, `log` |
  | `admin` | medium | `admin`, `is_admin`, `role`, `privilege`, `superuser`, `sudo`, `root`, `staff`, `permission`, `grant`, `access`, `acl` |
  | `debug` | medium | `debug`, `test`, `dev`, `verbose`, `trace`, `internal`, `preview`, `beta`, `hidden`, `show`, `config`, `env`, `mode`, `dump`, `source`, `console` |
  | `id` | medium | `id`, `uid`, `uuid`, `guid`, `pid`, `user`, `username`, `account`, `customer`, `member`, `owner`, `number`, and `<object>id` |
  | `injection` | low | `q`, `query`, `search`, `s`, `keyword`, `term`, `filter`, `sort`, `sortBy`, `order`, `orderBy`, `column`, `field`, `table`, `where`, `select`, `sql` |

  The order is most specific first: `redirect_url` is a redirect and not an SSRF, `admin_id` is admin. `page`, `view` and `lang` are left plain on purpose: they are on almost every page, and a class on them would make every page a finding. The class is a guess from the name, so a finding says where to look, not that the bug is there: arjun only found that the parameter changes the response.
- **One entry per class and parameter set.** For each URL and method, the parameters of each class (and the plain ones) are a set. URLs with exactly the same set, method and custom headers share one entry. `/admin` with `debug` and `admin` is in two findings, one `debug` and one `admin`, so every parameter is in exactly one entry.
- **Findings** are the entries with a class. **Groups** are the plain ones.
- **`locations`** lists every URL of the entry, without the `origin`, sorted. URLs that differ in one number are one location with the numbers as a range: `/product/[1-30]`, `/p?id=[1-3,7]`. A number with a leading zero (`007`) is never part of a range. A URL's own `[` and `]` are written `%5B` and `%5D`, so a bracket in a location is always a range.
- **`origin`** is the scheme and host every URL shares. Locations are written without it. When the run covered several origins, `origin` is left out and locations are full URLs.
- **`method`** is arjun's method when it is not `GET`: `POST` (form body), `JSON` (JSON body) or `XML`.
- **`headers`** are the request headers arjun sent that are not among its defaults: the `Cookie` or `Authorization` you passed with `-- --headers`. The `Content-Type` arjun adds itself for `JSON` and `XML` is left out.
- **Ranking:** findings by severity, then confidence, then class (in the table's order, `rce` first), then the number of URLs, then the parameter names and `id`. Groups by the number of URLs, then the parameter names and `id`. The same input always gives the same order.
- **`id`** is the class (or `params` for a group) and a short hash of the class, method, custom headers and parameter set, so the same entry has the same `id` in the next run.
- **`raw`** is arjun's JSON exports, one per method, one after the other, saved to disk. `--input` reads that file, or any `-oJ` file. `--raw <file>` picks the path.
- **Summary** counts URLs, parameters (URL, method and parameter triples) and parameter names, and, on a live run, the targets arjun found nothing on: arjun's export does not list them.
- **Budget:** `--max-bytes` (16,000 by default) keeps the output bounded on huge runs. It cuts in this order until the JSON fits:
  1. group locations (each keeps its `count` of URLs);
  2. groups;
  3. the locations of the lowest-ranked findings, each keeping one location plus its `count`;
  4. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **Errors** say what to try next. If arjun is missing, the exit code is 2.

Fields an agent can rebuild are left out to save tokens:

- `method` is left out when it is `GET`, and `headers` when arjun sent only its defaults.
- `count` appears only when the budget cut `locations`.
- `confidence` appears only when it is not `matched`; every class rule is `matched`.
- `origin`, `omitted`, `errors` and `next` appear only when they are not empty.
- `budget` appears only when something was cut.

The JSON is compact (one line) by default because indentation costs 59% to 78% more tokens in the benchmark; `--pretty` indents it. `--format table` prints a short human view of the same result; it lists finding locations but only counts group URLs.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-u` / `-l` / `--input` | every host the scope names | one target URL (repeatable) / target file / existing arjun `-oJ` export (repeatable) |
| `--method` | GET | comma-separated methods, one arjun run each: `GET`, `POST`, `JSON`, `XML` (arjun `-m`) |
| `--wordlist` | arjun's (`large`) | `small`, `medium`, `large` or a file (arjun `-w`) |
| `--rate`, `--threads`, `--timeout`, `--delay` | | arjun `--rate-limit` / `-t` / `-T` / `-d` |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 16000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save arjun's JSON exports |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--arjun` | arjun | path to the binary |
| `--banner` | false | print the banner to stderr |

## Development

```bash
go test ./...
go vet ./...
bench/run.sh            # replay bench/fixtures and count tokens
LIVE=1 bench/run.sh     # start the local lab, run arjun again, refresh the fixtures
```

Standard library only. arjun runs as a subprocess, so the binary stays small and arjun can be updated on its own. Support for [x8](https://github.com/Sh1Yo/x8) as a second engine is planned.

## Responsible use

Only test what you are authorized to test. arjun sends many requests per URL, more with a bigger wordlist; keep `--rate` low on anything you do not own.
