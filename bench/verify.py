"""Checks that every arjun result is in a raijin-params result.

A result is one URL, method and parameter that arjun reported: arjun's JSON export maps each URL to its
method and the parameters that changed the response, and every parameter of every URL is one result. The
headers arjun sent that are not among its defaults are part of it (the Content-Type arjun adds itself for
the JSON and XML methods is ignored).

A result is present when a finding or group lists its URL (expanding "[1-5,7]" ranges and prepending
"origin" when the output has one), has the parameter in "params", has the same method ("method" left out
means GET) and has the same custom headers ("headers" left out means none). raijin-params writes a URL's
own "[" and "]" as %5B and %5D, so the check does too.

usage: python verify.py <arjun export>... <raijin.json>
       (an export file may hold several JSON objects in a row, like raijin-params' raw file)
"""
import json, re, sys

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
}

*exports, out = sys.argv[1:]
o = json.load(open(out))
origin = o.get("origin", "")


def objects(path):
    text, dec, i = open(path).read(), json.JSONDecoder(), 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return
        obj, i = dec.raw_decode(text, i)
        yield obj


def custom(method, headers):
    return {k: str(v) for k, v in (headers or {}).items()
            if DEFAULT_HEADERS.get(k) != str(v)
            and not (k.lower() == "content-type" and (method, v) in (("JSON", "application/json"), ("XML", "application/xml")))}


def expand(loc):
    m = re.search(r"\[([0-9,\-]+)\]", loc)
    if not m:
        return [loc]
    out = []
    for part in m.group(1).split(","):
        a, _, b = part.partition("-")
        for n in range(int(a), int(b or a) + 1):
            out.append(loc[: m.start()] + str(n) + loc[m.end():])
    return out


# index: (absolute URL, method, parameter) -> list of header sets of the entries that list it
index = {}
for kind in ("findings", "groups"):
    for x in o[kind]:
        for loc in x.get("locations", []):
            for u in expand(loc):
                for p in x["params"]:
                    index.setdefault((origin + u, x.get("method", "GET"), p), []).append(x.get("headers", {}))

miss, n = [], 0
for path in exports:
    for export in objects(path):
        for url, r in export.items():
            method = (r.get("method") or "GET").upper()
            h = custom(method, r.get("headers"))
            key = url.replace("[", "%5B").replace("]", "%5D")
            for p in r.get("params") or []:
                if not p:
                    continue
                n += 1
                if h not in index.get((key, method, p), []):
                    miss.append((url, method, p))

print(f"{n} arjun results (URL, method, parameter), {len(miss)} missing from output", "truncated" if o.get("budget") else "")
for m in miss[:5]:
    print("  MISSING", m)
sys.exit(1 if miss else 0)
