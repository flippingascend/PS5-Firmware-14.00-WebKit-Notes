# PS5 firmware 14.00 - WebKit regex and allocation notes

Research notes and working tools from probing the browser of a PlayStation 5 on firmware 14.00
from a page served through its own User's Guide. Everything here runs from ordinary web content
with no exploit, no debug hardware and no modified firmware.

Headline results, in full detail in `FINDINGS.md`:

* The regex engine still fails **21 of 98** cases ported from the five regression test files Apple
  added in commit `956f6fb`, identically on three runs, with three root causes - one of which
  (a forward `/u` scan that enters surrogate pairs) is not among the four bugs that commit fixes.
  V8 passes all 98.
* Two 1 GiB canvases kill the browser's WebContent process, and the error screen's OK button
  reloads the same URL, so it loops. A 2 GiB `ArrayBuffer` does the same with less code.
* **No memory-safety primitive was found.** Across 4,957 case executions and 26 runs, a 49 KB
  sentinel spray re-verified after every case never changed once.

## What is in here

```
FINDINGS.md              what was tested, what worked, what half worked, what looked like a
                         finding but was not, what failed, what was never tried
tools/
  regex_census.html      open in any browser: runs the 98 upstream cases and shows where the
                         engine disagrees - self-contained, no network, no dependencies
  regex_census.js        the same table for node
  ov_probe.html          the instrument: the full probe page the console loaded (140 cases)
  _mk_census.py          generates the two census files; refuses to build unless the table
                         reproduces the per-file census measured on the console
  _u_cases.json          the extracted case table (patterns, flags, inputs, expectations)
  _u_hw_all.json         the console's answer for every case, parsed from the log
server/
  ps5_server.py          the harness: DNS answers for guide hostnames, HTTPS serving, result log
  SERVER.md              how it works, how to run it, and why the cooldown exists
notes/
  RESEARCH_STATE.md      the running record, in order, including the wrong turns
evidence/
  cases-fw14-0933.txt    every case result of the 09:33 console run, as the console reported it
  console.txt            the console's own report line: UA, screen, cores
posts/
  X_POST.txt             short drafts of the same findings, measured against a 280 character post
MANIFEST.txt             md5 of every file here
```

## Quick start

    node tools/regex_census.js                  # the 98 upstream cases against your own engine
    open tools/regex_census.html                # the same thing, in a browser, with the console's
                                                # recorded answers in the last column
    python server/ps5_server.py                 # the harness, if you want to serve a console

The two census files and the probe need nothing installed. The server needs Python 3 only.

## Provenance

The console answers in `regex_census.html` are not typed in: they were parsed out of
`evidence/`, and `_mk_census.py` refuses to emit the census files unless the table it builds
reproduces the per-file divergence counts measured on the console (9 / 6 / 3 / 2 / 1). The case
table itself was extracted by running the original probe's own case definitions through node, so
the patterns and inputs are the probe's rather than a retyping of them.

The console numbers come from one PS5 on firmware 14.00, on 2026-10-08, over a local network.
They are reproducible on the same firmware; other firmware will differ, which is the point of
shipping the tool.

## Scope and care

The allocation section describes a denial of service against the console's browser: two large
canvas allocations, one page, no exploit. That is as far as it goes - it does not grant code
execution, and it is included because a crash with a reload loop is worth knowing about before
someone else finds it. Test only hardware you own.
