# PS5 firmware 14.00 browser research: what was tested, what it did

Target: PlayStation 5, firmware 14.00. Its browser reports

    Mozilla/5.0 (PlayStation; PlayStation 5/14.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15

and a capability census puts it at
`screen=1920x1080@1 cores=4`. Everything below was reached from ordinary web content: a page
served to the console's browser over its own User's Guide link, with no exploit, no debug
hardware and no modified firmware.

Goal: find a memory primitive reachable from that page. Result: **none found.** What follows is
what was found instead, what is a real result, what merely looked like one, and what was never
attempted - so that the next person starts where this stopped instead of repeating it.

## How to read this

* **The regex numbers are the only confirmed defect class here.** They come from Apple's own
expected values, ported case for case, not from anything written for this project, and they
repeat identically across runs. There is no "maybe the test cases are wrong" escape hatch: on the
same table, V8 disagrees with Apple on nothing.
* **F3 - the forward `/u` scan that enters surrogate pairs - is a spec-level defect, not a chain
candidate.** It is worth filing because it is a forward-path violation that Apple's own fix did
not close. It is not worth holding hoping it becomes memory corruption: the one unchecked read in
that code path (`reread(matchBegin + i)`, guarded only by an assertion compiled out in release)
needs a capture whose start is greater than its end, and roughly 1,300 hardware cases never
produced one.
* **If you want to keep pulling the regex thread, the useful half is the false positives** - a
negated lookbehind matching where it must not - rather than the cases where a match is missed.
That is where a wrong answer is a wrong answer *and* a wrong state, and it is where further work
should aim. Nothing observed in this set suggests memory involvement either way.
* **The memory result is a negative from a write-only instrument.** 49 KB of patterned content,
re-verified after every case, so a write into that region is caught. It cannot see a pure read, it
cannot see a write that lands outside the region, and it cannot force a particular heap layout.
"No primitive" therefore means exactly: none of these ~5,000 cases produced one.

## Method

A probe page is served to the console through the User's Guide link. The console's browser
loads it, runs a numbered list of cases, and posts each result back to the server, which
appends it to a log. `ov_probe.html` holds the current case set; `ps5_server.py` is the server;
`notes/RESEARCH_STATE.md` is the running record of every run.

The oracle for memory damage is a spray of **24 `ArrayBuffer`s of 2048 bytes** (49,152 bytes),
each filled with a position-dependent pattern and **re-verified after every single case**. If a
case writes out of bounds into that spray, the next verification reports which buffer and which
byte changed. A deliberate write is injected once at start-up to prove the detector fires, so a
run with no corruption is a run where the instrument was armed. Across the whole session:
**4,957 case executions, 26 completed runs, 0 detected corruption.**

## Confirmed results

### 1. Regex: 21 of 98 upstream cases still fail, deterministically

The engine disagrees with Apple's own expected values on 21 of the 98 cases ported from the five
regression test files added by commit `956f6fb` (320492@main, 2026-09-04), which is twelve days
before firmware 14.00 shipped:

| section | source file | cases | divergences |
|---|---|---|---|
| A1 | character-class-non-bmp | 19 | 9 |
| A2 | fixed-count-non-bmp-character | 13 | 6 |
| A3 | surrogate-half | 11 | 3 |
| A4 | greedy-class-backtrack-non-bmp | 10 | 2 |
| A5 | lookbehind | 45 | 1 |

Same 21, same answers, on three separate runs (09:33, 09:46, 09:52). On the identical table, V8
(Node 24) diverges on **0 of 98**, so the expectations are not the problem.

All 21 are wrong answers or false positives, with three root causes:

* **F1** - a sticky `lastIndex` inside a surrogate pair is not mapped through the code point
  list.
* **F2** - the backward class/atom path walks a surrogate pair as two code units.
* **F3** - the forward `/u` scan enters pair interiors, so a pair's lead can be consumed as a
  standalone character. This is a **forward-path** violation and is *not* among the four bugs
  that commit 956f6fb fixes, which makes it the most independently reportable item here.

`tools/regex_census.html` (or `node tools/regex_census.js`) reproduces the whole table on any
engine in one file with no dependencies.

### 2. Memory exhaustion: a cheap renderer kill

* A **2 GiB `ArrayBuffer`** kills the renderer outright - the case announces itself, then the
  process is gone, with no result line (seen three times).
* A **1 GiB canvas** did the same, six times.
* Two 1 GiB canvases take down the WebContent process: white screen, the message *there is not
  enough free system memory*, and **pressing OK reloads the same URL**, so an accidental link
  into it is a loop rather than a one-off crash.

This is a denial of service from ordinary web content, not an exploit, and it is the least
interesting result here - but it is real, one page long, and reproducible.

## Partial results

* **Allocation ceiling.** 64, 128, 256 and 512 MiB `ArrayBuffer`s allocate and fill in 5-79 ms;
  a 512 MiB `Uint8Array` and a 64 MiB string are fine; an 8192x8192 canvas (256 MiB) allocates,
  draws and reads back. Between 512 MiB and 2 GiB the behaviour is **unmapped on purpose**:
  every attempt to narrow it costs the browser, and a killed page ends the run.
* **Size and offset arithmetic (section J).** 20 boundary cases over clamping APIs: 20 of 20
  match V8 exactly, including a refusal of anything at or past 2^31 pixels. A clean negative.
* **Payload parsers (section N).** 12 hand-built malformed payloads - WOFF2 and SFNT headers
  that lie about table counts and offsets, PNG/GIF/WebP/AVIF headers with impossible sizes,
  malformed deflate and gzip streams - were **all refused**, with no corruption. Two controls
  load a real 58 KB font over the wire and through a `data:` URL and both report `LOADED`, so the
  refusals are the parsers' own verdicts rather than a fetch layer rejecting the vehicle.
* **The media stack: mapped, not tested.** `canPlayType` answers *probably* for H.264, H.265,
  AV1, VP9, AAC and Opus; `MediaSource` exists; `isTypeSupported('...mp4; codecs="avc1..."')` is
  true. A full demuxer and decoder stack is therefore reachable from the guide page and **no
  probe has been aimed at it yet**.

## Things that looked like findings and were not

* **`px=0` in the glyph check.** An empty top-left corner was being sampled while the glyph was
  drawn 40 pixels lower, so the readback could not have failed. The replacement counts ink over
  the whole canvas and reports `ink=605` for the same two glyphs. The instrument was broken, not
  the engine.
* **Two apparent regex divergences (A4-06, A5-08).** They came from comparing a log value that
  encodes every non-ASCII character as `\uXXXX` against an expectation holding the real
  character. The engine never diverged on those two.
* **"25 of 102".** An earlier count in the notes. The ported set is 98 cases, not 102, and four
  of the 25 were cases written here rather than ported from Apple. The correct statement is
  **21 of Apple's 98**.
* **`canPlayType` vs `isTypeSupported`.** The first says AV1 is *probably* playable, the second
  says AV1 is not supported. That is a discrepancy in what the engine claims, **not** evidence of
  a decoder bug - the decoders have not been fed anything yet.
* **"Local storage does not persist."** Wrong: the first load had simply never written the key.
  `localStorage`, `sessionStorage` and `caches` all exist and work.
* **A duplicated case id (N-10).** A copy-paste error that would have made the case count read
  141 instead of 140 and broken the only number used to detect a lost run.

## Dead ends, so nobody repeats them

* **Regex as a route to memory corruption.** Six probes, roughly 1,300 cases, every divergence
  characterised: **zero** inverted capture ranges, **zero** ranges outside `[0, length]`, **zero**
  foreign code units, **zero** nondeterminism, and no read at or past the end of the subject even
  when the pattern asks for units that do not exist. One unchecked read exists in the code
  (`reread(matchBegin + i)`) but it is guarded by an assertion that is compiled out in release,
  and it needs a capture whose start is greater than its end - nothing in the whole space
  produced one.
* **These APIs are absent on firmware 14.00**, so no probe here can go further:
  WebAssembly, `SharedArrayBuffer`, WebGL and WebGL2 and WebGPU, `OffscreenCanvas`,
  `ImageDecoder` / `VideoDecoder` / `VideoFrame`, **all of WebAudio** (`AudioContext`, its
  `webkit` aliases, `OfflineAudioContext`, `AudioBuffer`, `AudioWorkletNode`), `serviceWorker`,
  `indexedDB`, `RTCPeerConnection`.
* **Canvas and allocation size arithmetic.** Every case matches the reference engine; there is
  nothing to report.
* **1 GiB canvas cases** were removed from the probe: they only kill the browser.
* **A `?again=1` bypass of the one-run-per-client limit** did not work, because the limit lives
  in the server rather than in the URL - the console simply re-ran the fatal group five times in
  41 seconds. The limit is now a 45-second cooldown per client with an inert countdown page.

## Not tried

* **Media decoders.** MP4, H.265 and AV1 samples through `<video>` and `MediaSource` - the
  largest untested surface that the census says is reachable.
* **The 512 MiB - 2 GiB allocation band**, deliberately left unmapped.
* **`structuredClone`, `Atomics`, `Worker` / `SharedWorker`, `caches`** - present, never probed.
* **Anything after the parsers in fonts, images and compression**: the refusals are clean, but
  only the payload shapes listed above were tried.
* **Heap-layout-dependent faults.** A linear sentinel sweep cannot see a use-after-free whose
  write lands in memory that is still valid, and it cannot force a particular layout.

## Limits of these results

* A negative is bounded by what was authored. "21 of 98" is exact; "no memory primitive" means
  none of the ~5,000 cases written here produced one.
* The sentinel spray detects writes into 49,152 bytes of known content. It cannot detect a read,
  and it cannot detect a write that lands anywhere else.
* The case count is the integrity check for a run: a run that reports anything other than the
  expected number lost a case, and the last `TRY` line with no matching `OK` line names it.
* The census page has not yet been run *on the console* - its PS5 column holds values recorded
  from the 09:33 run, not a live read.

## Reproducing

* On any engine: open `tools/regex_census.html`, or run `node tools/regex_census.js`.
* On a console: run `server/ps5_server.py`, point the console's DNS at the host, and open the
  User's Guide. `server/SERVER.md` explains the routing, the cooldown and the log format.
