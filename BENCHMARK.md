# Token benchmark: arjun vs raijin-params

How many tokens does an AI agent spend reading the result of a parameter discovery run, and does it lose anything? This benchmark runs arjun against a local lab, counts the tokens in each output shape, and checks that every arjun result is in the raijin-params output.

Reproduce: `bench/run.sh` replays the saved runs in `bench/fixtures`. `LIVE=1 bench/run.sh` starts the lab, runs arjun again and refreshes the fixtures first (two to three minutes; set `ARJUN=<path>` if arjun is not on `PATH`, and `PY=<python with tiktoken>`).

## Setup

- **Lab:** `bench/lab.py`, one Python process serving two sites on `127.0.0.1`, ports 19150 and 19151. Every page is the same on every request, and each hidden parameter adds a line to the body when it is present, so arjun finds exactly the parameters the lab reads.
  - **noisy** (`shop`, port 19150): a catalog. 30 product pages (`/product/1` to `/product/30`) that read `page`, `currency` and `format`, 15 articles that read `page` and `print`, and `/search`, which reads `q`, `sort` and `page`.
  - **findings** (`app`, port 19151): a small app. `url` and `callback` on `/fetch` and `/preview`, `next` on `/login` and `/logout`, `file` on `/download`, `template` and `lang` on `/render`, `host` and `cmd` on `/tools/ping`, `id` on `/api/user` and `/api/order`, `user_id` and `tab` on `/account`, `debug` and `admin` on `/admin`, `format` and `sort` on `/report`, `ref` on `/about`, and a POST form on `/login` that reads `username` and `password`. Only `/login` answers POST; the others answer 405.
- **arjun:** v2.2.7, with its `small` wordlist (835 names), 2 threads and `--rate-limit 50`. The noisy run uses `-m GET`; the findings run uses `-m GET` and `-m POST`.
- **raijin-params:** runs arjun itself (`-i <targets> -oJ <file> -q -m <method> -w small -t 2 --rate-limit 50`, once per method) and saves the exports, one after the other, as `raw`: that file is the fixture (`raw.json`). Defaults apply: no limit on findings, and `--max-bytes 16000`, which was not reached. All raijin-params rows replay `raw.json` with `--input`, so they see the same results.
- **Baselines**, as an agent would run arjun, with the same options:
  - `arjun -oJ`: arjun's JSON export, the `raw` file. For the findings run it is the GET export and the POST export together.
  - `arjun -oJ`, no headers, compact: the `raw` file with the request headers removed (arjun writes its 6 default headers for every URL) and without indentation. arjun has no option for this; it is what an agent gets by piping the export through a script or `jq`.
  - Text: arjun's default output (stdout and stderr, colors and progress lines included), from a separate run per method, saved as `text.txt`. Each run found the same URLs.
  - `arjun -oT`: arjun's text export from the same separate runs, one URL per line with the parameters filled with made-up values, saved as `text_ot.txt`.
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy

46 URLs, 123 parameters (6 names). raijin-params returned 1 finding (`/search` with `q` and `sort`, injection, low) and 3 groups: `/product/[1-30]` with `currency`, `format` and `page`, `/article/[1-15]` with `page` and `print`, and `/search` with `page`.

| Output | Bytes | Tokens | vs. arjun -oJ |
|---|---:|---:|---:|
| arjun `-oJ` | 25,633 | 7,530 | 1× |
| arjun `-oJ`, no headers, compact | 3,977 | 1,303 | 5.8× |
| arjun text (stdout+stderr) | 83,701 | 38,814 | 0.19× |
| arjun `-oT` | 2,964 | 1,302 | 5.8× |
| **raijin-params JSON (default)** | 575 | **185** | **41×** |
| raijin-params `--pretty` | 942 | 294 | 26× |
| raijin-params `--format table` | 221 | 72 | 105× |

## Scenario 2: findings

13 URLs, 22 parameters (18 names), from 14 arjun results (13 GET and 1 POST). raijin-params returned 12 findings and 5 groups.

- high: `cmd` on `/tools/ping` (rce), `url` and `callback` on `/fetch` and `/preview` (ssrf), `host` on `/tools/ping` (ssrf), `file` on `/download` and `template` on `/render` (file);
- medium: `next` on `/login` and `/logout` (redirect), `admin` and `debug` on `/admin`, `id` on `/api/order` and `/api/user`, `user_id` on `/account`, POST `username` on `/login` (id);
- low: `sort` on `/report` (injection);
- groups: `format`, `lang`, POST `password`, `ref` and `tab`.

| Output | Bytes | Tokens | vs. arjun -oJ |
|---|---:|---:|---:|
| arjun `-oJ` | 7,417 | 2,213 | 1× |
| arjun `-oJ`, no headers, compact | 1,025 | 347 | 6.4× |
| arjun text (stdout+stderr) | 19,533 | 9,055 | 0.24× |
| arjun `-oT` | 667 | 312 | 7.1× |
| **raijin-params JSON (default)** | 1,879 | **574** | **3.9×** |
| raijin-params `--pretty` | 3,472 | 1,021 | 2.2× |
| raijin-params `--format table` | 784 | 237 | 9.3× |

In a live run (not a replay) the raijin-params JSON also has `raw`, the path of the saved exports: 17 tokens for a default temp path like `/tmp/raijin-params-3172893561.json`.

## Nothing is lost

For each scenario, `bench/verify.py` checks every arjun result against the raijin-params output. A result is one URL, method and parameter: every parameter of every URL in every export of the `raw` file. The headers arjun sent that are not among its defaults are part of it. A result is present when a finding or group lists its URL (after expanding `[1-30]` ranges and prepending `origin`), has the parameter in `params`, has the same method (`GET` when `method` is left out) and has the same custom headers (none when `headers` is left out).

- Scenario 1: 123 results, **0 missing**.
- Scenario 2: 22 results, **0 missing**.

The unit tests cover the rest of the lossless rules on `testdata/sample.json` (custom headers, the JSON method, duplicates across exports, an out-of-scope URL): every in-scope URL, method and parameter is in exactly one entry.

## Reading the numbers

- **Noisy:** the same parameter set on 30 and 15 URLs is one entry each, and a run of URLs is one location (`/product/[1-30]`), so raijin-params is 41× smaller than arjun's JSON and 7× smaller than its smallest text export.
- **Findings:** every URL has its own parameters, so there is little to collapse. raijin-params is 3.9× smaller than arjun's JSON, and 16× smaller than arjun's default output, which is mostly progress lines. It is **1.8× larger** than `arjun -oT` (312 tokens) and 1.7× larger than the JSON without headers (347 tokens): the ids, severities and classes that rank `cmd`, `url` and `file` above `ref` and `tab` cost more than a bare URL list. `-oT` also has no ranking and writes made-up values into every URL, so an agent has to strip them to tell the parameters apart.
- **Indentation** (`--pretty`) costs 59% more tokens on the noisy run and 78% more on the findings run, which is why compact is the default.
