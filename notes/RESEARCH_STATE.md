# PS5 14.00 JSC Exploit Research — State Summary
## Date: 2026-10-07

## CONFIRMED WORKING PRIMITIVES

### 1. Controlled Sort Read-UAF (M1 confirmed)
- Fill Float64Array (RAB-backed) with any 64-bit pattern via mkFloat(lo,hi)
- Resize to 0 inside first comparator call
- Sort reads 79 values from freed backing (stale C++ m_vector ptr)
- 100% match — any bit pattern injectable and recoverable
- **Limitation**: reads only what WE put there (allocator zeroes on free)

### 2. forEach Write-UAF (F5/H6 confirmed)
- ta.forEach: resize at idx=0, write ta[idx]=val for remaining indices
- Writes SIZE values to freed backing store
- Up to 1024 bytes of controlled write
- **Limitation**: writes to RAB backing pool (completely isolated from JS heap)

### 3. JIT Spray (L3/L4 confirmed)
- 1000 eval-created functions in 29ms
- Float64 constants preserved perfectly in JIT code
- eval() and new Function() both work
- Template literals work via eval()

### 4. Dynamic Code Execution
- eval(), new Function(), template literals via eval — all available
- Once PC control achieved, trivial to execute arbitrary JS → syscalls

## FUNDAMENTAL BARRIERS

### RAB Pool Isolation
- JSC's ResizableArrayBuffer uses a completely separate allocator (IsoHeap)
- No JS allocation of ANY type ever aliases freed RAB VA
- Tested: Float64Array, plain Array, objects, plain ArrayBuffer — all separate
- Allocator ZEROES memory on free — no free-list ptr leaks via sort read

### Sort Pre-Copy Architecture
- sort() pre-copies all elements BEFORE first comparator call
- After resize(0), sort reads from freed backing (not pre-copy)
- BUT: sort on already-0-byte RAB makes 0 comparisons (aborts)
- Cannot chain: forEach-write + sort-read on same RAB
- Cannot chain: sort-read + RAB2 alias (pool isolation)

### JSC Property Hardening
- TypedArray: cannot defineProperty (accessor OR non-writable) on integer indices
- TypedArray: cannot freeze
- DataView: hard brand check on all method calls
- All wrong-receiver attempts throw immediately

### JIT Hardening
- All OOB array accesses return undefined (not raw memory)
- Type confusion (shape change) deopts cleanly, returns NaN/correct type
- BCE (bounds check elimination) maps OOB to undefined, not raw reads
- JIT closure correctly sees RAB resize (no stale cached value)

## UNEXPLORED ANGLES (lower probability)

1. **JSC compiler bugs** — specific CVEs in WebKit 605.1.15 vintage
   - Would need source code diff of PS5 JSC vs open-source WebKit
   - Possible target: CVE-2023-42917 (JSC JIT OOB) — needs research

2. **Worker threads** — postMessage with SharedArrayBuffer patterns
   - SAB not available, but Worker IS available
   - Could probe Worker heap layout via timing

3. **CSS/DOM layer** — not explored at all
   - WebKit's CSS parser has historically had bugs
   - DOM manipulation with large node trees
   - MutationObserver + DOM tree modification mid-callback

4. **fetch/XMLHttpRequest with crafted responses**
   - MIME type confusion in response parsing
   - Large response body triggering buffer realloc

5. **Canvas/WebGL** — if available
   - Not tested; could expose native code paths

6. **Audio/Video APIs** — if available
   - Not tested

## WHAT A FULL EXPLOIT WOULD NEED

Step 1: addrof primitive (get JS object address as float)
Step 2: fakeobj primitive (construct fake JS object at controlled address)  
Step 3: Build arbitrary read/write from addrof+fakeobj
Step 4: Find JIT code buffer address
Step 5: Write shellcode to JIT buffer
Step 6: Call into shellcode → kernel exploit

## CURRENT STATUS

All JSC-level attack surfaces in the "fast path" category have been probed.
The RAB-based primitives are real but operate in an isolated memory pool.
No addrof/fakeobj primitive found despite extensive probing.

Next most promising: DOM/CSS layer attacks and specific CVE research.

---

# CORRECTION — 2026-10-08: the "BS-series aliasing" result is RETRACTED

`grow_uaf_probe.html` (run on real hardware 06:53, log in `ascend_raw.log`) reported
"BS4: reliable aliasing! total=44" and "BS6: 0x20/0x3b/0xea/0x16/0x08 present".
**Both are measurement artifacts, not aliasing.** Do not build on them.

### Why BS4 is a false positive
- Payload is `u8r[i] = (i & 0xFF)` -> the array's own contents ARE the bytes 0..255.
- Marker is `0xA0 + run` (160..167) -> already one of those payload values.
- `ctrl4 = new Uint8Array(SZ)` is allocated **BEFORE** `rab4.resize(0)`, so it can
  never occupy the freed slot: the slot is not free yet when ctrl4 gets its home.
- `reads4.push(a)` pushes elements of u8r, so `v === marker4` is true whenever the
  element with that value is compared — guaranteed hits with **zero** aliasing.
- Confirms it: runs 1-7 (markers 0xA1..0xA7, all payload values) still showed 1-4
  hits each. run0's 32 hits = value 160 being used as a comparator operand.

### Why BS6 is a false positive
- Same 0..255 payload. `0x20 0x3b 0xea 0x16 0x08` are ALL <= 255, so "present".
- `0x00` reported **absent** — yet `ctrl6[5..7]` are zeros. If the reads had really
  come from ctrl, 0x00 would have appeared. Its absence proves the reads came from
  the payload's own values instead.

### Consequence
- The barrier "**no JS allocation of any type ever aliases freed RAB VA**" is
  **NOT** refuted. RAB backing lives in a separate allocator/isolated heap from the
  JSC heap and from ordinary JS typed-array backings.
- BS1/BS2 (F64 grow -> 0 stale reads) and BS5 (Uint16Array(128) wrong size class)
  are consistent with the barrier and remain valid.

### Rule adopted for all future probes
1. A reclaimer array must be allocated **INSIDE the free window** (after
   `resize(0)`), i.e. inside the callback that performs the resize.
2. A verdict must compare bytes **element-wise** against the reclaimer, never count
   value matches against a payload that already contains those values.
3. Every probe needs a **no-free control** block that must report zero matches.

## find_uaf_probe.html (v3) — RAN on real hardware 2026-10-08 07:04, now superseded
`PAGE = "find_uaf_probe.html"` in ps5_server.py. Blocks:
- **BT0** control, no `resize(0)` — must report `tailMatch=0`. (Locally: PASS)
- **BT1** direct `u8[i]` after free: detached (`undefined`) vs stale pointer; also
  tests whether direct-index WRITES alias.
- **BT2** forEach with NO reclaim — census of what freed backing actually holds
  (payload intact / zeroed / foreign).
- **BT3** forEach + single reclaimer allocated in the window -> `tailMatch`.
- **BT4** 8 reclaimer candidates in the window (beat the size-class lottery).
- **BT5** 16 runs of the BT3 shape — honest reliability count.
- **BT6** aliased WRITE through the stale view into a reclaimer in the window.

### RESULT — run on real hardware 2026-10-08 07:04 (raw log: ascend_raw.log)
BT0 PASS: `tailMatch=0/255 0xAA_hits=0` -> probe validity confirmed, no false positives.

**BT2 is the decisive answer and it is a HARD NEGATIVE:**
`reads=256 ... census: 0x55=1 undefined=255`
- `reads=256` proves forEach DID iterate the full cached length, so the loop window
  exists and the length IS captured before the detach.
- but all 255 element reads after `resize(0)` returned `undefined`.
=> the detached guard is applied at **value-read** time, NOT at length capture.
=> there is NO stale m_vector read through `u8[i]` / forEach / map.
=> a byte can NEVER be leaked through element access on this build.

BT1: `undefined=16/16` before AND after 4 candidates; writes dropped
     (`candidates_containing_0x77=none`, 0 bytes). Direct indexing fully guarded.
BT3: tailMatch=0/255, 0xAA_hits=0 -> no reclaim (reclaimer WAS allocated in-window).
BT4: bestCand=-1 bestTailMatch=0 -> no reclaim by any of 8 candidates.
BT5: 16 runs totalTailMatch=0 runsWithPtrTail=0 -> never reclaims.
BT6: `0x77 per candidate=[0,0,0,0]` -> no write alias.

### The only path that still reads freed memory: sort
`TypedArray.prototype.sort` was ASSUMED to sort IN PLACE through a raw data pointer
captured before the loop, so that `resize(0)` inside the comparator would leave
std::sort operating on freed memory. Under that assumption the BS-series "real values
after a resize" were retained payload bytes rather than leaked foreign data.

**THIS ASSUMPTION IS UNVERIFIED — see the CV0 gate under the RESULT below.** If the
engine pre-copies the elements, sort never touches the freed block at all, and both
the BS-series sort findings AND the CU1..CU9 sweep are measurements of a private copy.

Correction to an earlier note: BS6 did not fail because sort "scrambled the byte
order". It failed because of the payload collision proved above (0x00 reported absent
while ctrl6[5..7] are zeros). There was never a foreign read to reorder.

## sort_reclaim_probe.html — RAN 2026-10-08 07:12, but its INSTRUMENT VALIDITY was never established
`PAGE = "sort_reclaim_probe.html"`. Uses sort's raw stale read as a MEASURING
INSTRUMENT to sweep which allocation can claim a freed RAB backing block.
- **CU0** control, no resize -> `nonPayload=0` required
- **CU1** resize(0), no plant -> `afterResize=0` means no stale window exists at all
- **CU2** resize(0) then resize(256) -> does the allocator hand the block back?
- **CU3** Uint8Array(256)=0xAA   **CU4** plain ArrayBuffer(256)=0xBB
- **CU5** resizable ArrayBuffer(256)=0xCC   **CU6** Uint8Array(1024)=0xDD
- **CU7** JS Array(64) + JS String(200)   **CU8** 8x Uint8Array(256)=0xEE
- **CU9** Uint8Array(65536)=0x99

The first non-zero `nonPayload` identifies the reclaiming allocation family, and
that is the whole game. CAUTION: sort WRITES into the stale block, so a successful
reclaim can scribble over that candidate and take the browser down. Inherent to the
instrument, not a bug. DECISION POINT: if CU1 `afterResize=0`, there is no stale
window even for sort, the RAB line is CLOSED, and the work pivots to DOM/CSS + CVEs.

### RESULT — run on real hardware 2026-10-08 07:12
CU0 PASS (`nonPayload=0`), CU1 `afterResize=1023 nonPayload=0 undef=0`, and EVERY
reclaim candidate came back `nonPayload=0 undef=0`:
CU2 (same RAB regrown), CU3 Uint8Array(256)=0xAA, CU4 plain ArrayBuffer(256)=0xBB,
CU5 resizable ArrayBuffer(256)=0xCC, CU6 Uint8Array(1024)=0xDD,
CU7 JS Array(64)+JS String(200), CU8 8x Uint8Array(256)=0xEE, CU9 Uint8Array(65536)=0x99.

=> Under the IN-PLACE assumption, nothing claims a freed RAB backing block: not a
   same-size typed array, not a plain/resizable ArrayBuffer, not a JS Array, not a
   JS String, not a different size class. 17 candidates kept alive across the sweep.

**BUT the CU1 premise is unfounded as written.** The payload is all 0x55, and a
PRIVATE COPY of an all-0x55 payload also returns 0x55 — byte-identical. CU1 therefore
cannot distinguish "sort reads the freed block" from "sort reads its own copy", and
if it is a copy then CU3..CU9 prove nothing about reclaim either.

### CV0 — the instrument validity gate (added to sort_reclaim_probe.html)
Needs no free, no reclaim, no crash risk. Start the sort, and in the FIRST comparator
call overwrite the LIVE vector with `fill(0x99)`:
  in-place  -> later comparator args are 0x99
  pre-copy  -> later comparator args stay 0x55
Node/V8 reports `saw0x99=0 saw0x55=1023` => V8 PRE-COPIES. That validates the
discriminator (it detects a pre-copy engine) but says nothing about JSC.

=> STATUS: SETTLED on real hardware 2026-10-08 07:28 — see the CV0 result section at
   the end of this file. JSC PRE-COPIES, so CU1 is FALSE and CU3..CU9 are VOID.
   (Historical text of the original STATUS line follows: "the RAB line is UNRESOLVED,
   not closed. Re-read CU1..CU9 only after
   CV0. If JSC also pre-copies, `sort` is not an instrument at all, the BS-series
   "sort reads freed backing" claim is equally unfounded, and NO read or write of
   freed RAB memory has ever been demonstrated on this build.
=> Either way the practical position is unchanged: no usable primitive exists yet,
   and the work pivots to DOM/CSS surfaces + CVE triage (see UNEXPLORED ANGLES).

## DNS blocking + console-log hardening (2026-10-08)
1. `[DNS→BLOCK]` flood suppressed. Each blocked DOMAIN prints ONCE, repeats are
   silent, and a one-line rollup prints every 15s (`BLOCK_ROLLUP_SEC`) with total and
   distinct-domain counts. Verified against the real block: 1 call -> 1 line, 21
   calls -> still 1 line, new domain -> 2 lines, window elapsed -> rollup.
2. `is_blocked()` gained a SUBSTRING rule (`BLOCK_MARKERS`). The suffix-only rule let
   `gst.prod.dl.playstation.net.edgesuite.net` resolve, because it ends in
   `.edgesuite.net` — so the console could still reach Sony's CDN. Now BLOCKed.
   Guide domains are matched FIRST in run_dns(), so manuals/document.playstation.net
   are still SERVED (verified against 13 real hostnames from the 07:12 log).
3. `p()` made unbreakable. `_safe()` maps only a fixed glyph set — `→` (U+2192) and
   `—` (U+2014) pass through unchanged, and its final utf-8 encode/decode round trip
   is a no-op. On a redirected (non-console) stdout a print raises
   UnicodeEncodeError, and the DNS loop wraps its whole body in a bare `except: pass`
   BEFORE `s.sendto()`, so a failed print used to drop the DNS answer silently. `p()`
   now retries with an ASCII-replaced string and swallows the error. Verified: a raw
   print of `→` on a cp1252 stream raises; `p()` with the same text does not.

## LAUNCHER — START_SERVER.bat is the canonical one (2026-10-08)
START_SERVER.bat is correct as-is and is what actually launches ASCEND:
    @echo off
    cd /d "%~dp0"
    "C:\Program Files\Python311\python.exe" ps5_server.py
    pause
Quoted path, foreground run, `pause` so errors stay on screen. Left untouched.

run_ascend.bat was the BROKEN launcher (an earlier edit of mine, not what you run):
    cmd /c "chcp 65001 >nul & %PYTHON% ps5_server.py > server.log 2>&1"
with `%PYTHON% = C:\Program Files\Python311\python.exe` **unquoted** -> cmd split the
path at the space -> `'C:\Program' is not recognized as an internal or external
command`, and the window closed instantly. That stale message is why server.log
looked like the server was failing. run_ascend.bat now delegates to START_SERVER.bat
so there is a single source of truth.

START_HERE.bat is STALE: it starts `psn-dns-blocker/psn_block_dns.py` and calls
`send_elf.py scan` expecting `payload.elf`, but the psn-dns-blocker directory and
payload.elf do NOT exist in this folder (send_elf.py does exist). It belongs to the
older Okage/save-exploit toolkit and will not run as written.

---

# CV0 RESULT — REAL HARDWARE 2026-10-08 07:28: JSC PRE-COPIES => RAB LINE CLOSED

    CV0: readsAfterFirst=1023 saw0x99=0 saw0x55=1023 other=0

After the first comparator call overwrote the LIVE vector with 0x99, all 1023
remaining comparator arguments were STILL 0x55. The comparator is fed from a private
COPY, so `TypedArray.prototype.sort` never reads the backing store during the sort.
PS5/JSC behaves exactly like Node/V8 on this discriminator.

## What this settles
- `CU1` "RAW STALE READ CONFIRMED" is FALSE — its 0x55s came from the copy.
- `CU3..CU9` returning 0 proves NOTHING about reclaim. Treat that sweep as VOID,
  not as a negative result.
- The BS-series premise "sort reads 79 values from freed backing" is FALSE. Every
  sort-based measurement in this project measured a copy.
- `resize(0)` inside a sort comparator creates NO UAF window of any kind.

## Combined with the BT-series, the whole line is closed
- element reads after `resize(0)` -> `undefined` (BT2 census 0x55=1 undefined=255)
- element writes after `resize(0)` -> silently dropped (BT1-c: 0 bytes)
- sort -> operates on a copy, never touches the backing (CV0, this run)
=> There is NO JS-reachable path into a freed RAB backing store on PS5 14.00,
   whether or not any allocation would reclaim it. Do not spend more hardware runs
   on the RAB resize/free angle.

## Still unknown, and now moot
Whether any allocation reclaims a freed RAB block. It cannot be observed from JS
without a read primitive into the block, and none exists. Academic unless a new
primitive appears.

## The one real positive from this run
`CV1: reads=1497 attributable=1497 unattributable=0`, reads like `20@1 34@3 48@5 62@7`.
The bijective payload works and the detector is sound: any byte outside our payload
would have been flagged unattributable. REUSE THIS PAYLOAD SHAPE in all future probes
— it is the permanent fix for the artifact class that produced BS4's bogus 44 hits.

## NEXT: pivot
No JS-heap or RAB memory primitive survives. Per UNEXPLORED ANGLES, move to the
DOM/CSS parser surfaces and targeted JSC CVE triage for this WebKit build.

---

# SPECIES LINE CLOSED ON HARDWARE — 2026-10-08 07:44 (`species_oob_verify.html`)

Method: hand the species constructor a view over OUR OWN 4 KB buffer, so any write
beyond the view's declared length lands where we can observe it. No heap-adjacency
luck required, plus a positive control.

    SP0 (CORRECTLY sized species)  -> PASS: 64 doubles written into our buffer
                                      => the detector provably sees writes
    SP1 zero-length species        -> oobNonZero=0, TypeError
    SP2 one-element species        -> oobNonZero=0, TypeError
    SP6 1000-elem src, zero-length -> oobNonZero=0, TypeError
      JSC error: "TypedArray.prototype.map constructed typed array of insufficient length"
    SP3 Array source, map          -> oobNonZero=0, TypeError
    SP4 filter/concat/flat/flatMap -> oobNonZero=0, TypeError
      JSC error: "Attempting to store out-of-bounds property on a typed array at index: 0"
    SP5 object-returning map       -> bits 0x7ff8000000000000 (canonical NaN), no cell tag

## What this closes
1. **"OB1 OOB write via undersized species Float64Array" is refuted.** JSC explicitly
   detects the out-of-bounds store and throws BEFORE writing. The old ascend_raw.log
   line "OB1 HIT: OOB write via undersized species Float64Array!" was a false positive.
2. **Bug 2 / `cWrite` is not a primitive.** Its Proxy trap receives the engine's
   legitimate CreateDataPropertyOrThrow calls and then does `dst[d] = Number(...)`,
   an ordinary bounds-checked write into an array the caller already owns. "8/8
   CONFIRMED" was the probe reading back its own writes.
3. **Bug 1 ("ArraySpeciesCreate 0-Bug, NOVEL/UNREPORTED, CVE-worthy") is spec.**
   ECMA-262 mandates ArraySpeciesCreate(O,0) for filter/concat/flat/flatMap and
   (O,len) for map. The recorded 0,0,0,0 / map=4 IS the specification.
4. **Bug 6 (object capture in a Proxy trap) is a Proxy working as designed.**
5. **Bugs 3/4 (RAB UAF read/write) are dead** — element reads return `undefined`
   after resize(0), element writes are dropped, sort pre-copies (CV0, 07:28).

## Honest status
**Every primitive in ASCEND_PROMPT.md is now refuted.** There is no addrof, no fakeobj,
no OOB write, and no readable/writable freed memory. What survives is the probe
discipline: positive controls, element-wise comparison, bijective payloads, and
instrument-validity gates. That discipline is what caught all of the above, and it
must gate every future probe before a hardware run is spent.

---

# GOAL + STRATEGY — 2026-10-08 (stage 1, browser code execution)

Bounty (bounties.fulu.org/bounties/playstation-5) needs a HYPERVISOR bypass enabling
alternate-OS boot on firmware 13.42+. That is 4 stages: browser -> kernel -> hypervisor
-> boot chain. **We are at stage 0/1 and only stage 1 is reachable with this setup.**
Decision taken: aim deliberately at stage 1 — a genuine browser code-execution primitive
on 14.00 — as the standalone goal. Also noted: claimant must be US-based (confirmed),
and Sony bug-bounty participation disqualifies.

## The method: N-DAY HUNTING, not original research
Writing a fresh JSC bug from scratch is not realistic. The workable route is to find a
bug already FIXED upstream that is still PRESENT in this build, then trigger it. WebKit
is open source, so the fix commits are public and diffable.

## Prime candidate: CVE-2025-43529
- WebKit use-after-free in **`ObjectAllocationSinkingPhase`** (a DFG optimizer phase).
- Actively exploited in the wild; emergency-patched Dec 2025 (with CVE-2025-14174, ANGLE OOB).
- Impact per public analysis: arbitrary code execution and memory read/write inside the
  WebContent renderer. It is the JIT bug in the public "DarkSword" iOS chain.
- **Browser-only and JS-reachable** — exactly stage 1, no kernel needed.
- Public material to work from:
  - github.com/0xjohnnydev/WebKit-UAF-ANGLE-OOB-Analysis (repo, analysis)
  - a writeup titled "The Death of the Sandbox: An Engineering Autopsy of CVE-2025-43529"
  - 8ksec.io "How browser exploits work: DarkSword iOS CVE-2025-43529"

## THE GATE FACT — and it is BAD NEWS for this candidate
**PS5 firmware 14.00.00 was released 16 September 2026** (14.10 followed ~1 Oct 2026).
CVE-2025-43529 / CVE-2025-14174 were emergency-patched **December 2025** — nine months
BEFORE this firmware shipped. Sony backports WebKit security fixes aggressively, so
CVE-2025-43529 is very likely ALREADY DEAD on 14.00. Do not sink time into it without a
direct vulnerability test.

### The trap in this whole approach — read carefully
**Sony backports security patches while FREEZING the feature set.** The UA still says
"Version/17.0" and early-2025 features are present. That means:
- neither the UA nor `engine_bracket_probe.html` tells us the SECURITY patch level;
- a low feature ladder does NOT imply unpatched — it just means no new features landed;
- conversely a bug can be dead even though the feature set looks old.
=> **The ONLY reliable test is to run the candidate bug's trigger directly and observe
   the differential: vulnerable builds crash/corrupt, patched builds do nothing.**

### Consequence for the n-day window
Any WebKit bug whose FIX predates ~August 2026 is probably already in 14.00. The huntable
window is roughly **bugs fixed upstream after the 14.00 engine snapshot (mid/late 2026)**.
That is a narrow window, and it is exactly why this bounty is still unclaimed at $37,875.
Candidates worth checking, in order of promise:
- **CVE-2026-48558** — WebKit use-after-free leading to code execution (in CISA KEV).
  Need its patch date; if it landed after the 14.00 snapshot it may be live.
- CVE-2025-43434 / CVE-2025-43441 — UAFs; check patch dates (2026).
- CVE-2025-43529 / 14174 — almost certainly patched on 14.00 (see above).

## ENGINE BRACKET RESULT — real hardware 2026-10-08 07:53 (`engine_bracket_probe.html`)
Feature level is FROZEN AT SAFARI 17.0 (a ~Sept 2023 fork):
- **present:** everything through 17.0 — RegExp `v` flag, `Set.prototype.union`,
  Resizable ArrayBuffer (incl. grow), `toSorted`, `with`, `Array.fromAsync`,
  class static blocks, `URL.parse`
- **absent:** everything from 17.4 up — `Object.groupBy`, `Map.groupBy`,
  `Promise.withResolvers`, `ArrayBuffer.transfer`, `Promise.try`, `Iterator.from`,
  Iterator helpers, `Float16Array`, `Uint8Array.fromBase64`, `toHex`, `RegExp.escape`

=> The engine is a ~Sept 2023 codebase carrying a THREE-YEAR security-backport tail.
=> The UA is honest about the FEATURE set and silent about PATCHES, so feature
   detection can NEVER tell us whether a given bug is fixed. Only a differential
   trigger test can. (Side note: my "URL.parse = 18.0" hint was wrong — its presence
   while 17.4 features are absent means it shipped at or before 17.0.)

### REVISED HUNT SPACE (this is the important consequence)
Not "fixes after mid-2026". It is: **JSC/DOM fixes made upstream after Sept 2023 that
Sony did NOT backport.** Prioritise **SILENT (non-CVE) memory-safety fixes in JSC trunk** —
these get no advisory, so a console vendor has nothing prompting them to backport. That is
the most likely live-bug category, and it is why this is a grind rather than a lookup.

### EB2 capability flags on 14.00 (affects which bug classes exist at all)
    webassembly=undefined   SharedArrayBuffer=undefined   Atomics=object
    WebGL=undefined   AudioContext=undefined   IndexedDB=undefined
    requestIdleCallback=undefined   crypto.subtle=object   hardwareConcurrency=4
    CompressionStream DecompressionStream TransformStream ReadableStream
    MessageChannel Worker WebSocket  -> all present
- **No wasm and no SAB**: no wasm bug classes, and Atomics cannot be used as a
  primitive without shared memory.
- Streams / compression / workers ARE present and remain genuinely untested surface.

## OPEN GATE NOW BLOCKING THE PLAN: is the JIT actually tiering?  (`jit_tier_probe.html`)
EB3 in the bracket probe showed NO speedup: `0.000020 -> 0.000018 ms/op` (~18 ns/op) =
interpreter speed. A tiered engine reaches well under 3 ns/op on such a loop.
**If DFG/FTL never engages, every JIT-phase bug class is unreachable** — including the
`ObjectAllocationSinkingPhase` family — and stage 1 must be fought in the interpreter
and DOM instead. That single fact decides which bug classes are worth hunting.

`jit_tier_probe.html` measures it decisively (4 workloads, escalating passes, plus a
steady-state series). Reference run in a JIT-enabled engine (Node/V8):
    JT1 int-add 4.7 ns/op, float-sqrt 2.2, prop-store 6.1, f64-array 1.3
    JT2 4.8 -> 4.8 -> 0.5 -> 0.8 -> 0.8 -> 0.5 ns/op      <- tier-up signature
    JT3 eval-created code reaches 0.6 ns/op
Interpretation on the PS5: flat ~15-20 ns/op with no decline = JIT is NOT tiering.

### JT VERDICT — real hardware 2026-10-08 07:57: THE JIT DOES NOT TIER UP
    JT1 int-add     20.0 -> 16.0  -> 16.0  ns/op   (flat)
    JT1 float-sqrt 150.0 -> 140.0 -> 139.3 ns/op   (flat)
    JT1 prop-store  80.0 ->  80.0 ->  79.7 ns/op   (flat)
    JT1 f64-array  140.0 -> 136.0 -> 134.7 ns/op   (flat)
    JT2 six passes  18.0 -> 15.5 -> 15.0 -> 15.0 -> 15.5 -> 14.5 ns/op  (NO decline)
    JT3 eval code   20.0 -> 15.5 ns/op             (not optimised either)
Reference, same probe in a JIT-enabled engine: int-add 4.7, float-sqrt 2.0,
prop-store 6.0, f64-array 1.3 ns/op, and JT2 declining 5.0 -> 0.5 ns/op (10x).
The PS5 numbers are internally consistent interpreter numbers: a JIT would run
float-sqrt at ~2 ns/op and we measure 139 ns/op.

=> **NO TIER-UP ON THIS BUILD. ALL DFG/FTL BUG CLASSES ARE UNREACHABLE** — including
the ObjectAllocationSinkingPhase family (CVE-2025-43529's class), DFG type confusion,
DFG OSR, and JIT bounds-check-elimination bugs. Do not spend hardware runs on them.
This is now a SECOND, independent reason CVE-2025-43529 is not the path.

### RETRACTIONS caused by this verdict
- "JIT Spray (L3/L4 confirmed) — Float64 constants preserved perfectly in JIT code":
  creating eval'd functions and seeing constants preserved proves NOTHING about
  compilation. There is no optimising JIT, so there was no JIT code to spray.
- "JIT Hardening — OOB accesses return undefined, type confusion deopts cleanly, BCE
  maps OOB to undefined": consistent with code that was NEVER optimised at all. These
  observations are reclassified as interpreter/baseline behaviour, not JIT behaviour.

### REVISED HUNT SPACE for stage 1 (no optimising JIT)
The bug must be reachable via the interpreter + builtins + C++ (DOM/parsers), which is
a LARGER and more diverse space than JIT bugs — and historically where many real
in-the-wild WebKit bugs live:
1. **DOM / parser bugs** — HTML, CSS, DOM mutation, canvas. No JIT required.
2. **Interpreter + builtin bugs** — String/RegExp builtins, typed-array exotic
   behaviour, Proxy/Reflect, iterator protocol, structuredClone, JSON, Intl.
3. **Streams / compression / fetch buffers** — all present per EB2, all C++.
4. **Yarr (RegExp JIT) is a SEPARATE engine from the DFG** — test whether it is enabled;
   if it is, RegExp JIT bug classes are back in play despite the DFG being off.
5. Spray/groom IS viable: JT4 measured 10.5M object allocs/sec and 2.5M
   Float64Array(64) allocs/sec on this build.

## Next actions, in order
1. Run `engine_bracket_probe.html` on the PS5. Its value is now the EB2 capability flags
   and a lower bound on the feature set — NOT a patch-level verdict (see the trap above).
2. Build a **candidate-vuln triage probe**: for each candidate JSC bug, run that bug's
   trigger pattern in isolation and record the differential (crash / corruption / nothing).
   A crash of the User's Guide renderer IS a valid positive signal; the page reloads.
   Start with CVE-2026-48558 and any 2026 WebKit fix whose date is after the 14.00 build.
3. For each bug: read its public fix analysis (WebKit is open source, fixes are diffable),
   extract the exact trigger conditions, and encode them as a probe.
4. Only when a trigger proves alive: build the chain (DFG/JIT bugs give object-address
   disclosure and arbitrary read/write -> JIT shellcode -> native exec in the renderer).

## Remaining genuinely untested surface
DOM/CSS parser paths, streams/decompression/fetch buffers, Worker boundary, and
engine-version bracketing (the UA claims 17.0 but the real patch level is unknown —
feature-detect `Object.groupBy`, `Promise.withResolvers`,
`ArrayBuffer.prototype.transfer`, `URL.parse`, `Set.prototype.union` to bracket it)
for targeted CVE triage.


## 2026-10-08 ~08:30 - INSTRUMENT CORRECTION: the JT verdict was measured with a broken benchmark

Self-audit of `jit_tier_probe.html` AFTER it ran (three defects found; two cosmetic, one fatal):

1. The printed size labels lie (`p2=5e5` printed as "1e6", `p3=3e6` printed as "1e7").
   The ns/op arithmetic is however CORRECT, so no number was miscomputed - this is why
   the earlier "52 ms but 17.3 ns/op" reading looked impossible and was not.
2. **The fatal defect:** all four JT1 workloads used `x=(x+(i*3))|0`-style arithmetic
   that overflows int32 on essentially every iteration. JSC's optimiser OSR-exits on
   int32 overflow, so those loops are JIT-HOSTILE by construction: a fully tiered engine
   can legitimately report interpreter-like numbers on them. Confirmed locally - the same
   loop in Node v24 measured 4.75 ns/op at n=3e6 but 0.662 ns/op at n=8e7, i.e. the
   small-n reading was warmup, not steady state.
3. **Timer quantisation:** this PC's `performance.now()` is quantised to 1 ms (measured:
   smallest nonzero delta over 200k samples = 1.000 ms). The old probe used `Date.now()`
   (also 1 ms) with passes of 2 ms / 8 ms, i.e. 2-8 ticks per reading.

None of this *reverses* the verdict - a JIT'd sqrt loop does not run at 139 ns/op - but the
evidence was far weaker than the record claimed. It is now re-tested with a valid instrument.

### New instrument (TM1 in `tm_sa_vf_probe.html`)
The two cleanest JIT discriminators that exist, both immune to the int32-overflow defect:
* **EMPTY LOOP FLOOR** `spin(n){for(i=0;i<n;i++){}}` - loop overhead only.
  LLInt/interpreter ~1.5-3 ns/op, baseline JIT ~0.4, DFG ~0.25.
* **MONOMORPHIC CALL** `s=tiny(s)` - interpreter pays a full call frame (~20 ns/op);
  DFG/FTL inline it (~0.5-0.9 ns/op). A ~40x gap.
* Adaptive sizing: n is calibrated per workload until one pass costs >= 40 ms, so no
  reading sits inside the timer quantum, and n climbs to ~1e8 for cheap workloads -
  the workload size that forces tier-up in any real JIT. n + achieved cost are echoed.

Local reference, SAME probe, Node v24 (best of 7, adaptive n):
    empty 0.363 | xor 0.463 | mono-call 0.926 | sqrt 1.050 | OLD/workInt 0.662 ns/op
    (all series flat = already at steady state)
A JIT-enabled engine therefore lands at empty < 0.5 and mono-call < 1.5 ns/op. The PS5's
old readings (16 ns/op and 139 ns/op for sqrt) are 20-300x those = what "interpreter" looks like.

Decision rule now recorded:
    empty < 0.9 AND mono-call < 4   => optimising JIT IS live -> ALL DFG bug classes REOPEN
    empty > 1.5 AND mono-call > 12  => interpreter only -> verdict finally confirmed properly

## 2026-10-08 - FIRST REAL HUNT: the RegExp `v` flag (unicodeSets)

Strategic reasoning, recorded because it is the first hunting decision that survives all
retractions:

* The engine's feature level is frozen at Safari 17.0 (~Sept 2023). Its NEWEST code is
  therefore exactly the 17.0 additions: `v` flag unicodeSets, `structuredClone`,
  `URL.parse`, `Array.fromAsync`, `Intl.Segmenter`, `ResizableArrayBuffer`, class static
  blocks. New code is where bugs concentrate, and late-2023 bugs in those features are the
  LEAST likely to have been covered by Sony's security-backport tail (no advisory -> no
  backport prompt). EB1 already proved `RegExp v flag` is PRESENT on this build.
* The `v` flag is special because it is implemented in **Yarr's C++ pattern compiler and
  character-class canonicaliser, not in DFG** - so it is fully reachable with NO optimising
  JIT. `\q{...}` string literals, set `--`/`&&`, nested classes and the `RGI_Emoji` family
  (`\p{RGI_Emoji}`, `Basic_Emoji`, `Emoji_Keycap_Sequence`, `Emoji_ZWJ_Sequence`,
  `Emoji_Tag_Sequence`) are "properties of strings" that only exist with `v`, and JSC's
  implementation of them required new ICU-backed set machinery.
* Cost is near zero and the oracle is clean: a WebContent crash reloads the User's Guide,
  and the probe posts every batch of 20 patterns BEFORE running it, so the last posted
  batch names the culprits and the next run bisects them.

`tm_sa_vf_probe.html` therefore ships: TM (JIT gate, corrected) + SA (one-shot full
attack-surface enumeration: globalThis/navigator/document/CSS/Intl own-property dumps plus
~70 targeted subsystem checks and functional smoke tests) + VF (78 curated v-flag edge
cases, then a deterministic 2000-pattern combinatorial fuzz over nested class set algebra).

## Long-standing hygiene fixes applied this session (these caused silent data loss before)
* `p()` in `ps5_server.py` is now unbreakable (print -> ASCII-retry -> swallow). Reason:
  a failed `print` inside `run_dns()`'s bare `except: pass` silently DROPPED THE DNS ANSWER.
* `load_file`/GET now serve any file in DIRECTORY by basename; MIME map extended with
  jpg/gif/webp/bmp/tif/avif/svg/woff/woff2/ttf/otf/xml/xsl so binary decoder test assets
  can be served raw for the next probe.
* Probe sources are kept pure ASCII with an `esc()` helper that renders non-ASCII as
  \uXXXX in every report string - the server's stdout is a cp1252 cmd console and an
  unescaped emoji in a report would raise UnicodeEncodeError mid-handler.

## 2026-10-08 - BREAKTHROUGH LEAD: Yarr interpreter N-days (interpreter-only WebKit fixes)

Method: this is finally real N-day hunting with a diffable source, not speculation. WebKit is
open source; the fixes are public; and the commit messages *state the exact vulnerable and
fixed behaviour*. Enumerated `Source/JavaScriptCore/yarr/YarrInterpreter.cpp` history.

### Why the Yarr INTERPRETER is the right hunting ground for THIS engine
1. A JIT-less engine runs the Yarr interpreter for **every** RegExp. A normal Safari runs it
   only for patterns the RegExp JIT declines. So bugs that are "interpreter-only" are
   maximally reachable here and minimally reachable for everyone else - which is exactly why
   they go unnoticed, get no CVE, and have no advisory to prompt a vendor backport.
2. Commit 8c6275e says outright: **"Patterns with a lookbehind always run in the interpreter,
   so this reproduces with default options."** Those cases reproduce regardless of the JIT
   verdict, so this hunt does NOT depend on the TM gate.
3. Multiple fixes here are literally titled "Input Position Corruption" - position corruption
   in `tryConsumeBackReference` / `InputStream::reread` means indexing the subject string with
   a corrupted offset, i.e. an out-of-bounds read of the string buffer = heap disclosure.

### Fixes enumerated (all post-fork, all reachable without an optimising JIT)
| date | commit | subject |
|---|---|---|
| 2026-02-17 | 7f53c2a | word boundary assertion corrupting position with surrogate pairs (interpreter) |
| 2026-02-18 | f458b13 | tryConsumeBackReference pos corruption with surrogate pairs (interpreter) |
| 2026-05-11 | f44dcfd | **Input Position Corruption** in backreference backward matching via tryReadBackward surrogate rewind (credited to Junyoung Park / KAIST Hacking Lab) |
| 2026-07-22 | 8c6275e | InputStream::reread() checked the code unit AFTER a trail surrogate instead of BEFORE |
| 2026-08-10 | 6a1ef9a | interpreter should skip every once-through alternative after advancing start position |
| 2026-08-20 | 2165451 | tryConsumeBackReference must restore input position when a surrogate-pair read fails (failed greedy iteration CONSUMED INPUT) |
| 2026-08-21 | - | (follow-up, same function) |
| 2026-09-01 | 38281d0 | /v class: char after a class set operand adds U+0000 (stale cached m_character re-emitted) |
| 2026-09-08 | 1a29b8c | /v class: `\-` after a class set operand wrongly threw SyntaxError |
| 2026-04-25 | 1088aa8 | /v class: reject dangling hyphen in class set |
| 2025-05-22 | c07d637 | /v: nested inverted character classes handled incorrectly |

### Exact triggers + documented vulnerable-vs-fixed behaviour (encoded in the probe)
* `/\B./u.exec("\u{10000}\u{10000}")`  interpreter -> **null**; fixed -> match at 0.
  `/\B/u.exec("\u{10000}")` interpreter -> null; fixed -> match at 0.
  `readChecked()` had a side effect: reading a surrogate pair called `next()` and advanced pos.
  => doubles as a **behavioural RegExp-JIT oracle**, independent of any timing instrument.
* `/(?<=^)(...)\1/u.test("\uDC00\uD800a" x2)`  commit documents vulnerable = **false**, fixed = true.
* `new RegExp("(\u{1F601})\\1*$","u").exec("\u{1F601}ab")`  vulnerable = **matches**, fixed = **null**.
* `/(?<=\u{10000}\1*(a))b/u.exec("\u{10000}ab")`  fixed = `["b","a"]`.
* `/^[\q{ab}c]$/v.test("\u0000")`  vulnerable = **true**, fixed = false.
* `/^[[a]\-]$/v`  vulnerable = SyntaxError, fixed = compiles.

### Probe design consequence (this is the important part)
Every case asserts the value from the fix's OWN JSTest, and **all 28 cases were first validated
against a conformant engine (V8 via Node 24) where all 28 return the FIXED value**. So the
expectations are proven correct before the run: ANY case returning PRE-FIX on the PS5 is a real
finding, not a broken test. This is the instrument-validity discipline this project kept getting
burned by, applied up front instead of after the fact.

Then Y3 adds an actual memory-safety oracle rather than a correctness assertion: for each
candidate the input is padded with a single repeated filler code unit, and the match is checked
for (a) any code unit absent from the input, (b) a match end beyond the input length, (c) a
capture longer than the input, (d) nondeterminism across three identical calls. Any of those is
a genuine out-of-bounds read (heap bytes surfacing in `match[0]`) and would be a real primitive.
Stated limitation: an OOB read landing on a code-unit value that also occurs in the input is not
detectable this way.

## Also recorded: the corrected JIT gate (TM1) and the /v fuzz
`tm_sa_vf_probe.html` now runs, in order: **Y** (Yarr candidates - highest value, JIT-independent,
and it also answers the JIT question behaviourally), **TM** (corrected JIT gate: empty-loop floor
+ monomorphic-call inlining, adaptive n calibrated to >=40 ms per pass), **SA** (full attack-surface
enumeration), **VF** (78 curated /v cases + 2000-pattern combinatorial fuzz with a per-batch
heartbeat crash oracle). VF is last because it is the only section that can plausibly kill the
renderer, and a fresh [PAGE] load right after a posted batch names the culprits.

## 2026-10-08 08:21 - HARDWARE RUN OF tm_sa_vf_probe.html: 5 UPSTREAM YARR FIXES PROVEN ABSENT ON 14.00

### THE RESULT: Y SUMMARY reported 5 PRE-FIX cases
    C3  lookbehind backward-match backreference (position corruption)  got=null  want=["b","a"]
    C5a /v: char after set operand must not add U+0000               got=true  want=false
    C5c /v: nested \p{L} then char must not add U+0000               got=true  want=false
    C5e /v: escaped hyphen after set operand must compile            got=THREW:SyntaxError  want=compiled
    C5f /v: escaped hyphen after \q{} must compile                   got=THREW:SyntaxError  want=compiled

These are exact, upstream-documented vulnerable behaviours. All 28 Y expectations had first been
validated against V8/Node (all 28 return FIXED there), so these 5 are findings, not test bugs.

### C3 is the prize: an interpreter-only "Input Position Corruption" bug, still live
* Fix: f44dcfd / 313026@main, 2026-05-11, bugzilla 312690, **rdar://175122467**, credited to
  Junyoung Park (@candymate) of KAIST Hacking Lab.
* Subject, in Apple's own words: "**Input Position Corruption in Yarr Backreference Backward
  Matching via `tryReadBackward` Surrogate Pair Rewind**".
* Body: "This patch fixes position corruption in certain Yarr interpreter lookbehind cases by
  restoring the old position on match failure."
* Trigger, from the fix's own JSTest: `("" + /(?<=\u{10000}\1*(a))b/u.exec("\u{10000}ab"))` must
  be `"b,a"`. On PS5 14.00 it is **null** - the documented pre-fix value.
* Why this is the right kind of bug: it is a MISSING POSITION RESTORE. The rest of the match
  continues from a corrupted input offset, and the corrupted offset is used to index the subject
  string. That is the shape of an OOB read. It is also in the interpreter, i.e. in the code path
  this console always uses.
* Additional live signature: the SAME pattern returns **null** on the minimal input but a **clean
  match** on the 4004-char padded input (Y3 C3-padded) - input-dependent position corruption.
  Recorded as a lead, NOT as an OOB read: Y3 found no foreign code units, no capture longer than
  the input, no match extending past the input, and no nondeterminism on any candidate.

### The backport-tail model (this is the strategic consequence)
C1 (8c6275e, 2026-07-22) and C2 (2165451, 2026-08-20) came back FIXED. C3 (2026-05-11) and
C5 (2026-09-01/08) came back PRE-FIX. A monotonic timeline cannot explain that (a build that has
the July and August fixes must also have the May one). The consistent model, and it fits every
data point, is:

    These fixes target bugs INTRODUCED BY POST-FORK TRUNK REFACTORS that Sony's codebase
    never took. 2165451's own message says 280563@main introduced the early return it fixes,
    and 8c6275e's says the same refactor introduced the reread bug. Sony's older code simply
    does not contain that refactor, so those two inputs take a different, correct path.
    Fixes for LONG-STANDING bugs (missing position restores, a class-set state machine that
    predates 2026) are present as bugs because there was never a refactor to remove them.

CONSEQUENCE FOR HUNTING: **the older the bug, the more likely it is still there.** Prioritise
interpreter fixes from 2023-2025, not the newest ones. C3 is exactly such a long-standing bug.
Corollary: C1/C2 returning FIXED says NOTHING about Sony's backport tail - they are simply
not applicable - so no cut-off date can be inferred from them.

### Correction to the probe's own Y1 reading text (probe bug, not a finding)
The probe printed "FIXED on Y1a..Y1e but PRE-FIX on Y2 lookbehind cases => JIT is ON and paths
differ." That inference is FALSE and must not be carried forward. TM1 (below) proves there is no
JIT at all, so the only remaining explanation for Y1 is that the Feb-2026 word-boundary fix (or
its prerequisite) is present. Y1's five cases tell us nothing about the RegExp JIT.

### TM1 - the JIT gate, now measured with a VALID instrument (this supersedes the JT verdict)
Compared with the same probe on Node v24 (adaptive n, best of 7):
    workload     PS5 14.00     Node v24     ratio
    empty         6.625         0.363        18x
    xor           8.750         0.463        19x
    mono-call    38.000         0.926        41x
    sqrt        129.500         1.050       123x
    OLD/workInt  15.000         0.662        23x
    (i32store 37.0, i32read 24.75, dbladd 9.26, prop-add 17.25 on PS5; xor-minus-empty 2.13)
Every series was flat across all 7 passes at n up to 8e6 - no tier-up at any point, at a workload
size that forces tier-up in any real JIT. A 6.6 ns/op empty-loop floor means even the BASELINE JIT
is off, not just DFG/FTL. => `useJIT = false`, and since WebKit requires useJIT for the RegExp JIT,
`useRegExpJIT = false` too. **EVERY regex on this console therefore runs in YarrInterpreter**, which
is precisely where C3 lives. The old jit_tier_probe verdict is now correctly established rather than
merely suspected.
TM0: the PS5's `performance.now()` is quantised to 1.000 ms exactly like this PC's, so any pass
shorter than ~20 ms was pure quantisation noise - the adaptive sizing added for this run was
necessary, not cosmetic.

### SA - attack surface (763 globals; measured, not assumed)
ABSENT: WebAssembly, SharedArrayBuffer, WebGL/WebGL2, AudioContext/OfflineAudioContext,
IndexedDB (constructors present, `indexedDB` undefined - a Lockdown-Mode-style restriction),
OffscreenCanvas, ImageDecoder, XSLTProcessor, MathMLElement, RTCPeerConnection, ServiceWorker,
SharedWorker(no - present), Notification, SpeechSynthesis, PaymentRequest, Gamepad,
DeviceOrientation, Clipboard, requestIdleCallback, showOpenFilePicker, CSS.paintWorklet.
PRESENT and reachable: **the entire SVG filter surface** (SVGFilterElement, SVGFEImageElement,
SVGFEDisplacementMapElement, SVGFETurbulenceElement, every SVGFE* element, SVGAnimationElement,
SVGPathSeg*), createImageBitmap, ImageBitmap, Path2D, DOMPoint, FontFace + document.fonts,
Worker, SharedWorker, MessageChannel, BroadcastChannel, MediaSource + HTMLMediaElement,
crypto.subtle, CompressionStream/DecompressionStream/TransformStream/TextDecoderStream,
ReadableStream, structuredClone, FileReader, customElements, attachShadow, CSS.registerProperty,
Intl.Segmenter, Intl.DurationFormat, resizable ArrayBuffer.
SA3: canvas2d works; createImageBitmap decodes PNG and GIF but FAILS on an SVG blob
(InvalidStateError); DOMParser svg/xml/html all work; XSLT absent; deflate-raw, TextDecoder
(lenient 12 replacements / fatal TypeError), SHA-256 and Intl.Segmenter all work.
**Engine-bracket correction:** JSC is ~Safari 17.0 (EB1), but WebCore/ICU clearly are NOT:
`Intl.DurationFormat`, `CSSMathClamp`, `onbeforetoggle` and CSS container-query units (cqw/cqh/
cqi) are all post-17.0. So the DOM/CSS/Intl layer may be close to current while JSC is years old.
Caveat: presence of a constructor does not prove the feature is enabled. Strategic read: keep
hunting JSC/Yarr (measured old, and where C3 lives); deprioritise DOM/CSS N-days, which are more
likely to be already patched.

### VF - /v fuzz results
VF1 (78 curated cases): compiled=58, threw=20, all SyntaxError. Notable asymmetries worth chasing:
`[\p{ASCII}--\p{Digit}]` -> "invalid property expression" while the identically-shaped
`[\p{Letter}--\p{ASCII}]` compiles; and `\p{Emoji_Modifier_Sequence}`, `\p{Emoji_Flag_Sequence}`,
`\p{Emoji_Tag_Sequence}`, `\p{Emoji_ZWJ_Sequence}` ALL -> "invalid property expression" while
`RGI_Emoji`, `Basic_Emoji`, `Emoji` and `Emoji_Keycap_Sequence` work.
VF2 (2000 generated patterns): compiled=1248, SyntaxError=752, otherThrows=0, realMatches=179.
**Node/V8 produced 1248 / 752 / 179 on the identical corpus** - the generator is engine-neutral and
the two engines agree exactly on this corpus. No crash, no semantic divergence, no renderer death.
Negative result, honestly recorded: the combinatorial fuzz found nothing.

## 2026-10-08 08:31 - HARDWARE RUN OF lookbehind_probe.html: INVARIANT VIOLATED ON 14.00

### Result 1: the matcher returns matches whose index is INSIDE a surrogate pair (2 cases)
    INVARIANT[LB-DOC3] /(?<=$.*)/su on <emoji>  :: INDEX 1 IS INSIDE A SURROGATE PAIR | END 1 IS INSIDE A SURROGATE PAIR
    INVARIANT[LB-DOC4] /(?<=\uD83D)/u on <emoji> :: INDEX 1 IS INSIDE A SURROGATE PAIR | END 1 IS INSIDE A SURROGATE PAIR

`/(?<=\uD83D)/u.exec("\uD83D\uDE00")` returns a match at index 1 on a 2-code-unit string. In /u mode
the regex engine is required to operate on code POINTS; index 1 is between a lead and its trail, a
position the engine must never produce. This is not a wrong answer, it is an engine INVARIANT
violation, and it is now PROVEN on real hardware. It is exactly the pre-fix signature Apple
documented for bugs 3 and 4 of commit 956f6fb.

### Result 2: all four documented 956f6fb bugs reproduce, plus two MORE
    9 PRE-FIX cases:
      LB-DOC1 /(?<=[\u{1F600}a])b/u on "x<emoji>b"      got=null    want=[3,"b"]
      LB-DOC2 /(?<=\u{1F600}{2})x/u on "<2 emoji>x"     got=null    want=[4,"x"]
      LB-DOC3 /(?<=$.*)/su on "<emoji>"                 got=[1,""]  want=[2,""]     <- MID-PAIR
      LB-DOC4 /(?<=\uD83D)/u on "<emoji>"               got=[1,""]  want=null       <- MID-PAIR
      LB-DOC5  /(?<=\u{10000}\1*(a))b/u                 got=null    want=[3,"b","a"]  (C3)
      LB-DOC5b same, doubled input                      got=null    want=[3,"b","a"]
      LB-DOC5c same, pair at end of string              got=null    want=[3,"b","a"]
      ALT06 /(?<=abcd|bc)x/ on "abcdx"                  got=null    want=[4,"x"]     <- NEW, not documented
      ALT07 /(?<=bc|abcd)x/ on "abcdx"                  got=null    want=[4,"x"]     <- NEW, not documented

ALT06/ALT07 are discoveries of this project, not of any commit message: they appear only as
assertions in WebKit's own JIT test file, and the interpreter on 14.00 fails both. They are the same
alternation-order bug family as the documented ones (the backward alternative that should match is
missed when the longer alternative is listed second). This validates the test-corpus-as-oracle
method: reading the tests found real bugs that the commit messages never enumerate.

### Honest negatives from the same run
* The large-offset / INT32_MAX sub-family is NOT exploitable here: BIG01-BIG09 and all 7 EXTRA
  shapes returned the correct `null` (or the correct index for BIG06/07/09) in 0.0 ms each.
  `(?<=a{1073741824}x)b`, `(?<=(?:a{536870912}){2}x)b`, `(?<=a{2147483647})b`,
  `(?<=a{2147483648}x)b`, `(?<=.{1073741824})b` - all correct. Integer overflow in the lookbehind
  offset computation is closed.
* The capture/backreference machinery is mostly CORRECT: CAP01-CAP21 all pass, including the d-flag
  cases (CAP15 `indices.slice(1)=[[1,3],[3,5]]`, CAP20/21 indices.groups), replace (CAP17) and
  split (CAP18). And the `d` flag (hasIndices) IS supported on this build.
* ALT01-ALT41 pass except ALT06/ALT07, so 39 of 41 alternation assertions are fine - the bug is
  narrow and specific to alternation ORDER with differing lengths.
* Still no foreign code units, no oversized capture, no match past the input end, no nondeterminism.
  So the corrupted positions are real but have NOT yet been shown to read outside the string.

### What the next step must target, and why
The invariant violation gives us a matcher sitting at a position that is mid-pair. The step to an
OOB read is to make something READ a code point or a character class FROM that position:
* `Interpreter::checkCharacterClassDontAdvanceInputForNonBMP` and `testCharacterClass` are both
  named in the fix's changed-file list, so a character class evaluated against a NON-BMP subject at
  a mid-pair offset is the highest-value combination to try.
* Separately, the memory-unsafe path in this code area is `InputStream::reread(unsigned from)`:
  it indexes `m_input[from]` with only an `ASSERT(from < length)` (compiled out in release) and is
  called as `reread(matchBegin + i)` from `tryConsumeBackReference` using a CAPTURE's position. That
  is precisely the function Apple's C3 commit fixed ("restoring the old position on match failure").
  So: corrupt a capture's position via a failed backward iteration, then force a following
  backreference to reread from it, with the subject padded so a bad index lands in adjacent heap.
  Detection stays the same and is already proven: foreign code units in a capture.
## 2026-10-08 - THE LOOKBEHIND FAMILY: root cause identified (commit 956f6fb / 320492@main)

Commit 956f6fb (320492@main, 2026-09-04) - twelve days before PS5 fw 14.00 shipped (16 Sept 2026).
It is the second step of a three-step refactor chain: 319067@main -> 320492@main -> 320558@main.

Its commit message states the mechanism outright:

  "Until now the interpreter handled the direction term by term: each matching function had a
   Forward implementation and a separate Backward one. Those Backward implementations each
   re-derived the surrogate pair rules, and the ones that got them wrong are where the
   interpreter-only lookbehind bugs in /u mode came from."

So in the pre-refactor code every backwards-matching helper (`matchCharacterClassBackward`,
`consumeBackreferenceBackward`, the backward assertions, ...) carries its OWN copy of the
surrogate-pair logic, and a subset of those copies are simply wrong. That is why the family is
broad: the four bugs the commit lists are only the ones Apple chose to name, and the 08:31 run
finds at least two more in exactly the same family (ALT06/ALT07, below).

The fix's changed-file list names the memory-unsafe surfaces in this area:
  * `Interpreter::InputStream::reread(unsigned from)` - indexes `m_input[from]` guarded only by
    `ASSERT(from < length)`, and that assert is compiled out in release. It is called as
    `reread(matchBegin + i)` / `reread(matchEnd - i)` from `tryConsumeBackReference`, i.e. the
    index is derived from a CAPTURE's recorded position. If a capture's positions are corrupted
    such that start > end, `matchEnd - i` underflows and the read leaves the string.
  * `checkCharacterClassDontAdvanceInputForNonBMP` and `testCharacterClass` - the character-class
    path, i.e. what happens when a class is evaluated against a non-BMP subject.
  * `tryReadBackward` - the surrogate-pair rewind used by backward backreference matching.

Escalation routes from here (both encoded in `lb_escalate_probe.html`):
 (a) evaluate a CHARACTER CLASS against a NON-BMP subject at a mid-pair offset (targets
     `checkCharacterClassDontAdvanceInputForNonBMP` / `testCharacterClass`);
 (b) corrupt a CAPTURE's position via a failed backward iteration, then force a following
     BACKREFERENCE into `reread(matchBegin + i)`, padding the subject so a bad index lands in
     adjacent heap.
The detection oracle is proven and unchanged: foreign code units in a capture, a match index/end
inside a surrogate pair, an oversized capture, or nondeterminism. NEW oracle added for (b): a
capture whose `indices[i][0] > indices[i][1]` (the exact underflow precondition) or outside
[0, length], or a capture string whose length disagrees with its index range.

## 2026-10-08 08:31 - HARDWARE RUN OF lookbehind_probe.html: INVARIANT VIOLATED ON 14.00

### Result 1: the matcher returns matches whose index is INSIDE a surrogate pair (2 cases)
    INVARIANT[LB-DOC3] /(?<=$.*)/su on <emoji>  :: INDEX 1 IS INSIDE A SURROGATE PAIR | END 1 IS INSIDE A SURROGATE PAIR
    INVARIANT[LB-DOC4] /(?<=\uD83D)/u on <emoji> :: INDEX 1 IS INSIDE A SURROGATE PAIR | END 1 IS INSIDE A SURROGATE PAIR

`/(?<=\uD83D)/u.exec("\uD83D\uDE00")` returns a match at index 1 on a 2-code-unit string. In /u
mode the regex engine is required to operate on code POINTS; index 1 is between a lead and its
trail, a position the engine must never produce. This is not a wrong answer, it is an engine
INVARIANT violation, and it is now PROVEN on real hardware. It is exactly the pre-fix signature
Apple documented for bugs 3 and 4 of commit 956f6fb.

### Result 2: all four documented 956f6fb bugs reproduce, plus two MORE
    9 PRE-FIX cases:
      LB-DOC1 /(?<=[\u{1F600}a])b/u on "x<emoji>b"      got=null    want=[3,"b"]
      LB-DOC2 /(?<=\u{1F600}{2})x/u on "<2 emoji>x"     got=null    want=[4,"x"]
      LB-DOC3 /(?<=$.*)/su on "<emoji>"                 got=[1,""]  want=[2,""]     <- MID-PAIR
      LB-DOC4 /(?<=\uD83D)/u on "<emoji>"               got=[1,""]  want=null       <- MID-PAIR
      LB-DOC5  /(?<=\u{10000}\1*(a))b/u                 got=null    want=[3,"b","a"]  (C3)
      LB-DOC5b same, doubled input                      got=null    want=[3,"b","a"]
      LB-DOC5c same, pair at end of string              got=null    want=[3,"b","a"]
      ALT06 /(?<=abcd|bc)x/ on "abcdx"                  got=null    want=[4,"x"]     <- NEW, not documented
      ALT07 /(?<=bc|abcd)x/ on "abcdx"                  got=null    want=[4,"x"]     <- NEW, not documented

ALT06/ALT07 are discoveries of this project, not of any commit message: they appear only as
assertions in WebKit's own JIT test file, and the interpreter on 14.00 fails both. They are the
same family as the documented ones (the backward alternative that should match is missed when the
longer alternative is listed second). This validates the test-corpus-as-oracle method: reading
WebKit's tests found real bugs the commit messages never enumerate.

### Honest negatives from the same run
* The large-offset / INT32_MAX sub-family is NOT exploitable here: BIG01-BIG09 and all 7 EXTRA
  shapes returned the correct `null` (or the correct index for BIG06/07/09) in 0.0 ms each.
  `(?<=a{1073741824}x)b`, `(?<=(?:a{536870912}){2}x)b`, `(?<=a{2147483647})b`,
  `(?<=a{2147483648}x)b`, `(?<=.{1073741824})b` - all correct. Integer overflow in the lookbehind
  offset computation is closed.
* The capture/backreference machinery is mostly CORRECT: CAP01-CAP21 all pass, including the
  d-flag cases (CAP15 `indices.slice(1)=[[1,3],[3,5]]`, CAP20/21 indices.groups), replace (CAP17)
  and split (CAP18). The `d` flag (hasIndices) IS supported on this build.
* ALT01-ALT41 pass except ALT06/ALT07, so 39 of 41 alternation assertions are fine - the bug is
  narrow and specific to alternation ORDER with differing lengths.
* Still no foreign code units, no oversized capture, no match past the input end, no
  nondeterminism. The corrupted positions are real but have NOT yet been shown to read outside
  the string. That is precisely what `lb_escalate_probe.html` attacks next.

### Housekeeping note
The probe's own informational line "FIXED on Y1a..Y1e but PRE-FIX on Y2 => JIT is ON" (from
tm_sa_vf_probe.html) is FALSE and must not be carried forward: TM1 proves there is no JIT at all,
so Y1's five cases say nothing about a RegExp JIT. Already corrected in the 08:21 section above.
## 2026-10-08 08:50 - NEXT PROBE BUILT: `lb_escalate_probe.html` (mid-pair -> OOB escalation)

### What it is for
The 08:31 run proved the matcher produces positions INSIDE a surrogate pair. That is a wrong
answer until something READS through the bad position. This probe attacks the two read paths
that commit 956f6fb's changed-file list names:
  PATH 1  character class evaluated against a NON-BMP subject
          (`checkCharacterClassDontAdvanceInputForNonBMP`, `testCharacterClass`)
  PATH 2  `tryConsumeBackReference` -> `InputStream::reread(unsigned from)`, which indexes
          `m_input[from]` guarded only by `ASSERT(from < length)` - compiled out in release -
          and takes `from` from a CAPTURE position (`matchBegin + i` / `matchEnd - i`). If a
          capture's recorded start exceeds its recorded end, `matchEnd - i` UNDERFLOWS.

### Oracles (detector-only, no expectation needed)
  N1  match index or end inside a surrogate pair, or a capture boundary that splits one
  N2  a code unit in a capture that is NOT in the input     = out-of-bounds read
  N3  index < 0, end past the input length, capture longer than the input
  N4  indices[i][0] > indices[i][1]                         = the reread underflow precondition
  N5  range outside [0,length], or capture text length != range length
  N6  nondeterminism across a fresh regexp and the same instance
  N7  case slower than 2 s
N1 is guarded by the unicode flag: a mid-pair index is LEGAL without /u, so the detector only
fires for /u or /v regexps. The guard itself is part of the SELFTEST.

### Sections (124 cases)
  SELFTEST  4 synthetic matches fed straight to the detectors, with the required answer known in
            advance - so the probe can be shown to be capable of firing before it is trusted.
  EB1  character classes at and around the surrogate boundary, backward (28). Includes the three
       `[\uD800-\uDBFF][\uDC00-\uDFFF]` shapes whose spec answer is null, so a MATCH there is the
       pre-fix signature of a backward class matcher consuming a pair as two code units.
  EB2  the C3 family expanded: `\1*`, `\1+`, `\1?`, `\1{0,3}`, both lazy forms, two groups, the
       pair at front/middle/end, a lone lead, a lone trail, a nested lookbehind, and a named
       group with `\k<n>` (22).
  EB3  attempts to create start > end directly (12).
  EB4  regression controls: the four cases that came back FIXED at 08:21. They must stay fixed;
       a flip would mean an earlier reading was wrong.
  EB5  in-buffer overread: the subject is a SLICE of a larger string with U+E001..U+E004
       sentinels immediately before and after it, so a backward overread past the start or a
       forward overread past the end lands on a code unit that is not in the subject. 8 danger
       patterns x (pad 0, pad 1, pad 7, and a slice that starts mid-pair) = 32 cases.
  EB6  sticky with lastIndex placed INSIDE a pair (10). Spec (RegExpBuiltinExec with u/v): the
       input is the CODE POINT LIST, so a lastIndex inside a pair denotes the containing code
       point and the match must start at the PAIR START. V8 confirms `/./uy` with lastIndex=1 on
       <emoji> matches at index 0 with the whole emoji. An engine that matches AT the mid-pair
       index is starting from a position the matcher is required to reject - and this is the
       cheapest way to hand the matcher a corrupted position with NO lookbehind involved.
  EB7  derived-string paths that READ at the boundaries (12): replace with the right-context and
       left-context special patterns (literally substring(matchEnd,length) and
       substring(0,matchStart)), the replace callback offset, split, matchAll - and the C3
       lookbehind driven through replace/split/match as well as exec.
  EB8  amplification: 300 runs with /g of the four key patterns, checking for a change of result
       across runs or a spin.

### Validation, applied BEFORE the run (this project's instrument discipline)
  * 0 backticks, 0 non-ASCII bytes, `node --check` OK, 30,963 bytes.
  * Dry run on V8 (Node 24): 124 cases, 0 PRE-FIX, 0 spurious oracle notes.
  * The dry run CAUGHT FIVE WRONG EXPECTATIONS OF MINE before hardware, which is exactly why it
    exists:
      E1-04 / E1-05 / E1-10 - I expected `[3,"b"]` for `(?<=[\uD800-\uDBFF][\uDC00-\uDFFF])b`.
        Wrong: under /u the class holds CODE POINTS and a supplementary character is not in
        [D800,DBFF], so the spec answer is null. Kept, now with want=null - a MATCH there is the
        pre-fix signature.
      E4-04 - I expected the match at index 4; the lookbehind `(?<=^)` pins it to index 0.
      E7-11 - I forgot that `String.prototype.split` includes capture groups in its output, so
        that split has three parts, not two.
  * The SELFTEST proves the detectors can fire: mid-pair detector FIRED on a unicode regexp and
    SILENT for the same synthetic match without /u; inverted-range detector FIRED; foreign-unit
    detector FIRED.
  * `lb_escalate_v8_reference.txt` holds the full V8 dry-run output (124 CASE lines) so the
    hardware run can be diffed against a conformant engine case by case. A `got=` that differs
    from the reference is a divergence; `verdict=PRE-FIX` is stronger still, because those
    expectations come from the spec or from WebKit's own tests.

### Server state
PAGE = "lb_escalate_probe.html" (ps5_server.py line 78); the file compiles clean. MIME map and
the serve-any-basename GET behaviour are unchanged from the 08:31 run, so nothing else needed
changing.
## 2026-10-08 08:49 - HARDWARE RUN OF lb_escalate_probe.html: the mid-pair position is REAL and READABLE,
## but it does NOT read out of bounds

Mechanics: 124 cases; 121 posts reached `ascend_raw.log`; 3 were lost in flight (E1-26, E5000e,
E50048). The in-page SUMMARY counted 23 PRE-FIX while 22 lines are in the log, so the lost
known-answer case E1-26 returned the pre-fix behaviour. Full case-by-case comparison against the
conformant engine is saved as `lb_escalate_diff_vs_v8.txt`.

    known-answer PRE-FIX : 23 (22 visible in the log)
    divergences from V8  : 59 of 121 comparable cases
    oracle hits          : 10 of 124 - and ALL TEN ARE N1 (a position inside a surrogate pair)
    N2 / N3 / N4 / N5    : ZERO on real cases (the only occurrences are the SELFTEST's synthetic ones)
    slow cases           : 0 (worst case 1 ms); no nondeterminism anywhere

### THE HEADLINE - the memory-safety escalation FAILED, and it failed cleanly
N2 (a code unit in a capture that is not in the input), N3 (match end past the input, capture
longer than the input) and N4 (a capture whose recorded start exceeds its recorded end - the
precondition for the `reread(matchEnd - i)` index underflow) NEVER FIRED. This is a controlled
negative, not an empty experiment: the EB5 sentinel-slice cases reproduced the bug (they returned
mid-pair matches at indices 1, 2 and 8 in the sentinel-wrapped slices) and still produced no
foreign code unit in any capture. So the corrupted position is read INSIDE the string every time.
None of the 12 EB3 shapes produced a capture with start > end either, which is consistent with the
08:31 result that CAP01-CAP21 all pass: the capture bookkeeping is sound, so `matchEnd - i` never
goes negative. The family corrupts WHICH POSITION IS CONSIDERED VALID, not the indices handed to
the input-stream reader. That is the honest state of the escalation.

### F1 (NEW, and independent of the lookbehind family): a sticky lastIndex inside a pair is NOT
### mapped through the code point list
5 shapes (E6-01, E6-02, E6-03, E6-05, E6-10). Spec and V8: with u/v the input is the code point
list, so lastIndex=1 on a 2-unit emoji denotes the emoji itself and the match starts at index 0.
This build instead starts AT index 1:

    /./uy          lastIndex=1 on <emoji>        PS5 [1,"\uDE00"]   V8 [0,"<emoji>"]
    /[\s\S]/uy     lastIndex=1 on <emoji>        PS5 [1,"\uDE00"]   V8 [0,"<emoji>"]
    /(?<=.)/uy     lastIndex=1 on <emoji>        PS5 [1,""]         V8 null
    /(?<=\uD83D)(.)/uy lastIndex=1 on <emoji><emoji>
                                                 PS5 [1,"\uDE00","\uDE00"]   V8 null
The last one matters most: it yields a CAPTURE whose text is a lone trail surrogate, at a match
index inside a pair, from pure JS with no lookbehind bug involved. This is a second, independent
way into the corrupted-position state, reachable from any script via `re.lastIndex = k`.
E6-04/06/07/08/09 matched V8, so the divergence is specific to shapes that can consume a lone trail.

### F2 (NEW member of the 956f6fb family): the backward class path matches a surrogate pair as two
### CODE UNITS
    /(?<=\uD83D[\uDC00-\uDFFF])b/u on "x<emoji>b"   PS5 [3,"b"]   spec/V8 null
Four variants: E1-10 plus the sentinel-slice copies E5001f, E50020, E50021 (indices 2, 3 and 9).
Under /u the class operands hold CODE POINTS, so a supplementary character cannot satisfy
"U+D83D then a code point in [DC00,DFFF]" - the answer must be null. This build matches, i.e. the
backward character-class matcher walks code UNITS and re-combines the pair itself. That is exactly
the failure mode commit 956f6fb says the old Backward implementations were prone to
("each re-derived the surrogate pair rules, and the ones that got them wrong..."). Note the mirror
shapes E1-04/E1-05 (the same two ranges, ordered and grouped the other way) return null, so the
bug is specific to the lead-literal-then-trail-class form.

### F3: the mid-pair position is READABLE, and what comes out of it is a lone trail surrogate
    /(?<=\uD83D)./u       on <emoji>   PS5 [1,"\uDE00"]   V8 null
    /(?<=\uD83D)[\s\S]/u  on <emoji>   PS5 [1,"\uDE00"]   V8 null
plus E5003d / E5003e / E5003f in the sentinel slices (indices 1, 2, 8). So `readChecked` will
happily return the TRAIL half of a pair as a standalone character, and it does so at a
position that moves with the string's alignment - this is not a heap-layout accident.

### F4: the corrupted position reaches every derived-string sink
    E7-03  <emoji>.replace(/(?<=\uD83D)/u,"X")   PS5 "\uD83DX\uDE00"   <- a pair SPLIT IN TWO around X
    E7-02  <emoji>.replace(/(?<=\uD83D)/u,RIGHT) PS5 "<emoji>\uDE00"  <- appends a lone trail
    E7-05  <emoji>.split(/(?<=\uD83D)/u)         PS5 ["\uD83D","\uDE00"]
    E7-06  (EMO+EMO).matchAll(/(?<=$.*)/sug)     PS5 [[3,0],[4,0]]     <- an extra mid-pair match
    E7-10  <emoji>.search(/(?<=\uD83D)/u)        PS5 1                 V8 -1
    E7-04  replace callback offset               PS5 {"off":1,"len":2} V8 {}
    E7-01  replace with both context patterns    PS5 <emoji><emoji>    (matches V8 by coincidence)
E7-03 is the sharpest: a valid pair is turned into two ill-formed halves with a character inserted
between them, so any downstream consumer of that string receives ill-formed UTF-16. E7-04 is the
cleanest oracle for a JS-visible position leak: the callback reports offset 1 in a 2-unit subject.
The C3 lookbehind leaks through these sinks too (E7-08, E7-11, E7-12), and the whole E2/E3 family
sits in the 59 divergences, including one reverse case (E2-06, lazy `\1+?`: PS5 matches where V8
returns null).

### F5: regression controls held
E4-01, E4-02, E4-03 and E4-04 all returned the FIXED values again, so the 08:21 readings are
stable across runs and the instrument is consistent. The `d` flag, indices.groups and the
capture/backreference machinery all continue to behave.

### What this means for stage 1
The lookbehind/interpreter family is a rich source of WRONG ANSWERS and of ill-formed strings
observable from JS through exec/matchAll/search/split/replace and the replace callback. It has not
produced a memory-safety primitive: the reads stay inside the subject. Escalating further should
attack the READER rather than the scan position, and the newest evidence points at F2 - the
backward class matcher that consumes a pair as two code units - because that path advances the
input position by an amount the pattern does not expect, which is what a term AFTER it would then
act on. Concrete next shapes: the F2 prefix followed by a quantifier or a backreference
(`(?<=\uD83D[\uDC00-\uDFFF]\1*(a))b`, `(?<=\uD83D[\uDC00-\uDFFF]{2})b`), and combinations of the
F1 sticky entry (a capture recorded inside a pair) with a backward backreference.
## 2026-10-08 08:53 - REPLICATION RUN: complete 124/124 dataset, fully deterministic

A second run of the identical page (no code change at all - only the three posts that were lost
in flight the first time needed recovering). Result:

    run 08:49 : 121 cases, 22 PRE-FIX, 10 oracle-hit cases
    run 08:53 : 124 cases, 23 PRE-FIX, 10 oracle-hit cases
    labels shared by the two runs: 121  -  DIFFERING VALUES: 0
    run 2 vs the V8 reference: 60 divergences of 124 measured cases
    N2 / N3 / N4 / N5 on real cases, run 2: 0 / 0 / 0 / 0

Three things this settles:

1. The probe is DETERMINISTIC across runs. Every case that was logged twice returned the
   byte-identical value, so the earlier "no N6 nondeterminism" reading is now backed by a
   whole-run replicate rather than by three repeats inside one page. The cases that were
   unmeasurable in run 1 (E5000e, E50048, E1-26) all returned normally in run 2.
2. Run 1's reading is confirmed case by case, and the in-page PRE-FIX count of 23 (against only
   22 verdict lines in the log) is explained: the missing known-answer case
   E1-26 `(?<=\u{10000}{2})x/u` on <U+10000><U+10000>x returned null where the fixed answer is
   [4,"x"]. That is the 23rd PRE-FIX and the 60th divergence. The other two recovered cases
   (E5000e, E50048 - both EB5 sentinel slices) returned null, matching V8, so they add no
   divergence.
3. The memory-safety negative now rests on the COMPLETE dataset: with all 124 cases measured,
   N2 (foreign code units), N3 (oversized capture / end past input) and N4 (capture with
   start > end, the `reread` underflow precondition) still never fired on a real case. The
   sentinel-slice overread experiment reproduced the bug in run 2 as well (E5003d/e/f, indices
   1, 2, 8) and still leaked nothing outside the subject.

Artifacts: `lb_escalate_run2_diff_vs_v8.txt` is the full run-2 case-by-case diff (all 60
divergences with both values); `lb_escalate_diff_vs_v8.txt` is the run-1 equivalent.
### Third run, 08:56 - three-way agreement, two complete datasets

    run 08:49 : 121 cases, 22 PRE-FIX, 10 oracle-hit cases, 0 memory-safety-tag hits
    run 08:53 : 124 cases, 23 PRE-FIX, 10 oracle-hit cases, 0 memory-safety-tag hits
    run 08:56 : 124 cases, 23 PRE-FIX, 10 oracle-hit cases, 0 memory-safety-tag hits

    pairwise: 08:49 vs 08:53 -> shared 121, differing 0
              08:49 vs 08:56 -> shared 121, differing 0
              08:53 vs 08:56 -> shared 124, differing 0
    run 08:56 vs V8: 124 of 124 measured, 60 divergences (identical to run 08:53)

Two COMPLETE runs now agree on all 124 cases with not one differing value, and the partial first
run agrees with both on all 121 cases it managed to report. The engine's behaviour here is a
stable property, not a race: three page loads, ~370 case executions, zero variance. That closes
the determinism question for this probe, and the memory-safety negative (N2/N3/N4/N5 absent) is
now confirmed in three independent runs rather than one.
## 2026-10-08 09:08 - NEXT PROBE: `lb_f2_probe.html` (F2 x F1)

Built from the three-run result. The escalation question is now narrow: F2 - the lead-then-trail-
class lookbehind that MATCHES a surrogate pair as two code units where the spec answer is null -
is the only observed shape in this family that SUCCEEDS, so whatever follows the prefix is
evaluated at a position the pattern never intended. A wrong answer becomes a read only if a term
after the prefix acts on that position.

### Sections (70 cases)
    SELFTEST  unchanged: 4 synthetic matches prove the detectors can fire.
    G1 (12)  what follows the F2 prefix - quantifiers on the trail class: {1}, {2}, {1,3}, +, *?,
             +?, grouped (?:...){2}, {2,}, the whole prefix {2}, {3}, {0,1}, {9}.
    G2 (10)  what follows it - captures and backreferences: \1*, (a)\1, the prefix captured then
             \1, the prefix twice, \1{0,3}, \1+, \1?, \1{2}, the trail captured then \1, the lead
             captured then the prefix then \1.
    G3  (8)  capture boundaries INSIDE the prefix, which is where the d-flag indices oracles get
             their first real exercise inside this family: whole prefix captured, trail captured,
             lead and trail captured separately, nested captures, a named capture, then . reading
             after the prefix (both with and without capture).
    G4  (8)  the FORWARD / lookahead contrast. This is the diagnostic section: if the forward path
             does not match where the backward one does, the defect is localised to the backward
             helpers, which is exactly what commit 956f6fb describes. It also separates "a class
             recombines a pair" from "the literal lead matched a pair's lead" - different bugs.
    G5  (6)  F1 x F2: enter the matcher inside a pair with sticky lastIndex, then run the prefix.
    EB6/EB7/EB8 (26) kept as REGRESSION CONTROLS. All three runs produced byte-identical values
             for these, so any movement there means the engine changed under us.

Every G pattern must return null under /u on its subject, because a lone surrogate in the pattern
can never match part of a pair - so want='null' is authoritative and a MATCH is the finding.

### Five defects caught before hardware (the instrument discipline, working)
1. A stray `)` after each case label in the new G block - caught by `node --check`.
2. Single backslashes where the file's convention is doubled - caught by strict mode rejecting an
   octal escape ("Octal escape sequences are not allowed in strict mode").
3. The runner loop depended on `var i` declared in the EB1-EB5 block that the splice replaced, so
   the whole main function died with "i is not defined" and posted ZERO cases. Caught by the dry
   run showing 0 cases; fixed by making the loop declare its own counter.
4. `[\uD83D\uDC00-\uDFFF]` is not what I meant: in /u mode `\uD83D\uDC00` is a SURROGATE PAIR
   escape (U+1F600), so the class became a range from U+1F600 down to U+DFFF - out of order -
   and threw SyntaxError. V8 flagged all five. Replaced with `[\uD800-\uDFFF]`, which is a legal
   range and a cleaner test of the same idea.
5. An incorrect byte pattern in a patch (I dropped a `D` byte from `uD83D`) silently matched
   nothing; found by printing the actual line bytes rather than trusting the search count.

### Validation
    29628 bytes, 0 backticks, 0 non-ASCII, node --check clean
    dry run on V8: 70 cases, 0 PRE-FIX, 0 spurious oracle notes, SELFTEST 4/4
    reference saved as lb_f2_v8_reference.txt (70 CASE lines)
    PAGE = "lb_f2_probe.html"; ps5_server.py compiles clean

### How to read the hardware run
    G1-01 should reproduce E1-10 as a control: expect [3,"b"] on 14.00 vs null here.
    G5-04 should reproduce E6-01: expect [1,"\uDE00"] vs null here.
    G3-01..08: if they MATCH, the d-flag indices oracles run on real captures for the first time
        in this family - N4 (inverted range) or N5 (range outside input) firing there would be
        the underflow precondition the reread() path needs.
    G4: all null expected. A MATCH in G4-01..08 means the forward path is affected too, which
        would move the diagnosis off the backward helpers.
    G2: whether a term after the prefix still behaves as the pattern expects.
## 2026-10-08 09:10 - HARDWARE RUN OF lb_f2_probe.html: 36 PRE-FIX OF 70, and CAPTURES THAT SPLIT
## SURROGATE PAIRS - but still zero memory-safety signal

All 70 cases measured. 36 known-answer PRE-FIX (51%, against 23/124 in the previous probe - the
F2 line is far more productive than the general lookbehind sweep). 11 cases fired an oracle.

    oracle tags: N1 INDEX 6 | N1 END 1 | N1 group 6 | N1 named 1   = 14 N1 hits
                 N2 0 | N3 0 | N4 0 | N5 0 | N6 0 | N7 0
    full diff: lb_f2_diff_vs_v8.txt

### F3 (NEW, and independent of lookbehind and sticky): the /u FORWARD scan visits pair interiors
    /\uDE00/u.exec("<emoji>")   PS5 [1,"\uDE00"]   spec/V8 null
No lookbehind, no sticky, no quantifier - a plain forward pattern matching the TRAIL half of a
pair and reporting index 1, a position the /u matcher must never try. With the u flag the scan is
required to advance by code points, so index 1 should never be a candidate. This is a third,
independent producer of a mid-pair match, and the simplest one to state: the forward scan does not
skip pair-interior positions. (A lone-LEAD pattern cannot expose the same thing on this subject,
because no lead sits at a pair-interior position in it - so this is the only shape that shows it.)
G4-01, G4-06 and G4-08 all returned null as the spec requires, so the subclass is specific.

### F4 (NEW): captures whose recorded ranges SPLIT a surrogate pair
    G3-02 (?<=\uD83D([\uDC00-\uDFFF]))b     PS5 [2,"b","\uDE00"]            group[1] START MID-PAIR
    G3-03 (?<=(\uD83D)([\uDC00-\uDFFF]))b   PS5 [2,"b","\uD83D","\uDE00"]  group[1] END MID-PAIR,
                                                                          group[2] START MID-PAIR
    G3-04 nested captures                   group[2] END MID-PAIR, group[3] START MID-PAIR
    G3-05 named capture                     group[1] START MID-PAIR, named t SPLITS A PAIR
    G2-10 (?<=(\uD83D)[\uDC00-\uDFFF]\1)b   PS5 [4,"b","\uD83D"]           group[1] END MID-PAIR
Until now the corruption was confined to the SCAN position. G3-03 shows the engine recording two
captures that between them partition one surrogate pair - group[1] holding the lead alone, ending
mid-pair, and group[2] holding the trail alone, starting mid-pair - from a match that SUCCEEDS.
G2-10 goes further: a BACKREFERENCE was resolved against a capture whose end is mid-pair, and the
match still returned. Named groups do it too. This is the state the reread(matchBegin + i) path
consumes, so it is the closest we have come to the memory-unsafe reader.

### What did NOT happen (the honest status of the escalation)
N4 - a capture whose recorded start exceeds its recorded end, the precondition for the
`matchEnd - i` underflow - did NOT fire, and neither did N2 (foreign code units), N3 (capture
longer than input / end past input) or N5 (range outside [0,length]). So even with captures that
split pairs, every recorded range is still well formed and in bounds: start <= end, both inside the
subject. The corruption decides WHICH POSITIONS ARE LEGAL, and the bookkeeping around it remains
self-consistent. That is now the third probe in a row to hit this wall, and it is a strong
statement about the family: the interpreter's position corruption does not produce an
out-of-range index by itself.

### Control results worth keeping
    G3-01 (?<=(\uD83D[\uDC00-\uDFFF]))b     PS5 [2,"b","\uD83D\uDE00"]  the CAPTURE is the correct
        whole pair - it is the MATCH INDEX that is illegal - so the prefix's unit-walking does not
        always corrupt what gets captured.
    G1-01 [2,"b"]  G1-03 [2,"b"]  G1-04 [2,"b"]  G1-06 [2,"b"]  G1-09 [4,"b"]  G1-05/G1-08/G1-10/
    G1-11/G1-12 all null: only the greedy-plus and the bounded forms match; the lazy and
    over-long-quantifier forms do not. That is a useful shape constraint on the unit-walking.
    G2-01/G2-05/G2-06/G2-07/G2-09 all null (the C3-shaped backref-after-split-capture forms do not
    reproduce here); G2-03/G2-04/G2-08 match with the pair captured intact.
    G4-05 (?<=[\uD800-\uDFFF])b  PS5 [2,"b"] - the combined single-class form matches as well as
    the literal-lead form, so the bug is the class/atom path generally, not one spelling of it.
    G4-02/G4-03/G4-04 (two steps of the combined class) all null, forward and backward.
    G5-05 [2,"","\uD83D\uDE00"] - a zero-width match at 2 with a capture holding the whole pair.
    EB6/EB7/EB8 controls reproduced the previous three runs exactly, so the instrument is stable
    across pages.

### WHERE THE NEXT PROBE MUST GO
The single missing precondition is an INVERTED capture range (start > end). Everything else in
this family is mapped. The new material to attack it with is F4: captures that already hold half a
pair. The shapes to build:
  * a backreference to a split capture inside a NESTED lookbehind, so the inner matcher's
    recorded range is consumed by the outer one (group[1] END mid-pair feeding a backward read);
  * a quantifier over a split capture ((\uD83D){2} style) so the same half-pair capture is
    re-recorded at a shifted position;
  * the split capture inside alternations of differing length, i.e. the ALT06/ALT07 order bug
    combined with F4, since that family already produces wrong positions;
  * d-flag inspection of every one of those, hunting specifically for start > end.
Plus F3 as a separate, cleaner entry point: the forward scan that tries pair interiors can be
combined with a capture and a following term, e.g. /(\uDE00)(.)/u and /(\uDE00)\1/u, where the
second term must read from a mid-pair position with no lookbehind involved at all.
## SESSION 2026-10-08 (continued): the two patch texts, and the upstream suite probe

### 1. The carried-control claim is now mechanical, not eyeballed
_cc.py parsed both windows out of ascend_raw.log (08:56 = lb_escalate_probe.html, 09:10 =
lb_f2_probe.html): **26 carried E6/E7/E8 cases, 0 missing from the new page, 0 differing values.**
The claim made in the 09:10 write-up is therefore verified, not asserted. Script deleted.

### 2. The pre-fix source, read directly out of the patch texts
Both patches fetched in full: **956f6fb / 320492@main** (the lookbehind refactor) and
**f44dcfd / 313026@main** (C3, bug 312690, "Input Position Corruption in Yarr Backreference
Backward Matching via tryReadBackward Surrogate Pair Rewind"). The minus side of each hunk is the
code fw 14.00 ships. What matters:

```
char32_t NODELETE reread(unsigned from)
{
    ASSERT(from < length);            // compiled out in release
    auto result = input[from];
    if (decodeSurrogatePairs) {
        if (U16_IS_LEAD(result) && from + 1 < length && U16_IS_TRAIL(input[from + 1]))
            return U16_GET_SUPPLEMENTARY(result, input[from + 1]);
        if (U16_IS_TRAIL(result) && from > 0 && U16_IS_LEAD(input[from - 1]))
            return errorCodePoint;    // <-- a capture beginning on a TRAIL half
    }
    return result;
}

bool tryConsumeBackReference(int matchBegin, int matchEnd, ByteTerm& term)   // PRE-C3
{
    unsigned matchSize = (unsigned)(matchEnd - matchBegin);
    if (term.matchDirection() == Forward) {
        if (!input.checkInput(matchSize))   // <-- POSITION ALREADY MOVED BY matchSize
            return false;
    }
    unsigned savedPos = input.getPos();      // <-- saved AFTER the move
    for (unsigned i = 0; i < matchSize; ++i) {
        unsigned negativeInputOffset = term.inputPosition + matchSize - i;
        if (term.matchDirection() == Backward && negativeInputOffset > input.getPos())
            return false;                    // C3 adds setPos(savedPos) here
        char32_t oldCh = input.reread(matchBegin + i);
        char32_t ch;
        if (!U_IS_BMP(oldCh)) { ch = input.readSurrogatePairChecked(negativeInputOffset); ++i; }
        else ch = term.matchDirection() == Forward
                    ? input.readCheckedDontAdvance(negativeInputOffset)
                    : input.tryReadBackward(negativeInputOffset);
        if (oldCh == errorCodePoint || ch == errorCodePoint)
            return false;      // C3 restores here ONLY if (matchDirection == Backward)
        ...
    }
}
```

Readings that are new this session and are not in the earlier notes:

* **The forward direction has its own unrestored exit and C3 never covered it.** For a FORWARD
  backreference the position has already been advanced by matchSize, and the errorCodePoint exit
  restores only when matchDirection == Backward. So a forward backreference whose capture begins on
  a trail half returns false with the position left advanced by exactly matchSize and nothing puts
  it back. No lookbehind, no sticky, no corrupted capture range is required.
* **The trigger is producible from pure JS**, because F3 already gives a forward /u match at a pair
  interior (09:10, G4-07: the lone-trail pattern on one emoji returned a match at index 1). Capture
  that trail half, backreference it, and reread(capture.begin) is exactly the errorCodePoint input
  above.
* **956f6fb deletes every Backward implementation** and its message names the four bugs and the five
  test files it adds. Those five files carry Apple's own expected values, which is the strongest
  oracle this project has had: they are the fix author's own assertions, not recalled spec.
* The C3 test file asserts only the match TEXT ("" + m === "b,a"), not the index, so the index there
  is not an expectation. On a 4-unit subject "b" sits at index 3; V8 agrees; that is the value used.
* rewind(1) inside tryReadBackward is ASSERT(pos >= amount) only, no release check, but the offset is
  provably >= 1 at every call site, so it cannot be made to wrap by itself.
* checkCharacterClassDontAdvanceInputForNonBMP bails before reading when matchDirection == Backward
  and negativeInputOffset > input.getPos(), so the class path cannot go negative either.
* The only genuinely unchecked read in the whole family is still reread(matchBegin + i) / (matchEnd
  - i): an inverted capture makes matchSize huge, and the in-loop backward guard would bail at i = 0
  unless inputPosition + matchSize - 0 wraps to a value below getPos(), which needs a large
  inputPosition. Both halves remain unobserved - that is the wall, stated exactly.

### 3. New probe lb_u_probe.html (35,592 bytes, 187 cases) - INSTALLED as PAGE
Sections:
* **A1-A5, 102 cases** - the five test files added by 956f6fb, ported case for case with Apple's own
  expected values as the want field: character-class-non-bmp (19), fixed-count-non-bmp-character
  (13), surrogate-half (11), greedy-class-backtrack-non-bmp (10 of 14 - the four replace/matchAll
  ones are in D1 as derived strings), lookbehind.js (45, plus the four /gu lastIndex variants run in
  the L block). A mismatch in section A is a live interpreter-only lookbehind bug, not a guess.
* **B1** the C3 oracle in four spellings. **B2** the forward errorCodePoint family: a trail-half
  capture plus a backreference, with and without the u flag, literal and class spellings, sticky.
  **B3** eighteen shapes that give a position corrupted by a failed backreference somewhere to show:
  the poison in one branch of an alternation with a plain continuation in the other, inside
  lookaheads, inside captures, followed by dots, classes, fixed counts. **B4** amplification.
* **C1, 20 cases** - F1/F3 forensics: does the forward scan really try index 1, or does the engine
  report a shifted index for a match that started at 0? The anchored forms are the discriminator.
* **D1, 12 controls** - the exact values hardware measured at 09:10 (E7-03, E7-05, E7-12, E8-04 as
  derived strings, plus F1/F2/F3 exec values). These compare against the MEASURED value and report
  DRIFT; they are instrument checks, never passes.
* **L1, 12 cases** - sticky and global entry points with the position written back, including the
  poisoned backreference under /y and /g.
* Five SELFTEST detectors, all proven able to fire: mid-pair (fires under u, silent without),
  inverted range, foreign code unit, and the new **N8: group[0] text != substring(index, index +
  len)** - the matched text and the reported index disagreeing, which no correct engine can produce.
  **N14** also flags any single exec slower than 10 ms; every case in the last three runs measured 0
  or 1 ms, so that is far above the instrument noise and is the signature of the runaway loop a huge
  matchSize would cause.

### 4. V8 dry run: the transcription is faithful
0 of 183 cases mismatched on V8, all five SELFTEST detectors fired (SILENT only where required), no
THREW, no MAIN ERR. The eleven oracle hits in the dry run are the D1 controls drifting away from the
PS5's measured values, which is what a correct engine must do. Reference saved as
lb_u_v8_reference.txt. Two self-inflicted errors were found and fixed by this dry run (A5-03's
undefined group needs quotes in the JSON form, and B1-01..B1-04's index was 3, not 2), which is
exactly why the dry run exists.

### 5. Server
PAGE moved from lb_f2_probe.html to lb_u_probe.html on line 78. Byte-verified: 29,026 to 29,025
bytes, 712 CRs preserved in both, all other bytes identical, py_compile clean, __pycache__ removed.
The temporary backup was deleted - the change is a one-line rename.

### WHAT TO LOOK FOR IN THIS RUN
1. The **section A census**: which of the 102 upstream cases disagree. Grouped by file it says which
   backward sub-helper is wrong (class path vs fixed count vs surrogate half vs greedy backtrack) and
   whether the engine predates 956f6fb entirely.
2. **B2-01..B2-12**: the first lookbehind-free corruption entry. Are they null (bug unreachable), do
   they match with a shifted index, or does a following term read the wrong unit?
3. **B3-**, the decisive set: if a failed forward backreference leaves the position advanced, the
   continuation in the other branch must land on the wrong unit. A match whose text is shifted
   relative to its index is what N8 is for.
4. **N14 / TIMING**: any case over 10 ms. That is the runaway loop.
5. **N2**: the only oracle that proves an out-of-bounds READ rather than a wrong answer.
## 09:33 HARDWARE RUN of lb_u_probe.html - 25 of 102 upstream cases fail on fw 14.00

### How the run happened
The launcher question was answered by running ps5_server.py directly from a command line for 12
seconds. It bound :53, :80, :443 and :8765 (Windows needs no elevation for that), printed ASCEND
ONLINE and `Serving: lb_u_probe.html`, and during those seconds the console loaded the page twice
(09:33:41 and 09:33:45). The run completed inside the window: `lb_u_probe DONE` at 09:33:49.
Completeness is mechanical: **171 distinct CASE labels on hardware vs 171 in the V8 reference, 0
missing**, and the probe's own summary line agrees with the per-case lines (25 of 183).
`lb_u_diff_vs_v8.txt` holds all 67 divergences.

### THE CENSUS - Apple's own expected values, so nothing here is a guess
    A1 class/non-BMP in a lookbehind      9 of 19 fail
    A2 fixed-count non-BMP literal        6 of 13 fail
    A3 surrogate half                     3 of 11 fail
    A4 greedy class backtrack             2 of 10 fail
    A5 general lookbehind                 1 of 45 fail
    B1 the C3 oracle                      4 of 4 fail
The 25 failures, PS5 result first, V8 (spec) second:

    A1-01 (?<=[\u{1F600}a])b/u   on x<emoji>b     null      vs [3,"b"]
    A1-03 same under /v                            null      vs [3,"b"]
    A1-05 (?<=\p{L})b/u          on <U+10428>b    null      vs [2,"b"]
    A1-06 (?<!\p{L})b/u          on <U+10428>b    [2,"b"]   vs null        FALSE POSITIVE
    A1-08 (?<=[\u{10400}x])b/u   on <U+10000>b    null      vs [2,"b"]
    A1-11 (?<=^[\s\S])$/u        on <emoji>       null      vs [2,""]
    A1-12 (?<=[\s\S]{2})x/u      on a<emoji>x     null      vs [3,"x"]
    A1-18 (?<=\u{1F600}.)x/su    on <emoji><emoji2>x null   vs [4,"x"]
    A1-19 (?<=\p{L}\u{1F600}.)x/su null           null      vs [5,"x"]
    A2-01 (?<=\u{1F600}{2})x/u   on two pairs     null      vs [4,"x"]      (bug 2 in the commit)
    A2-02 same under /v                            null      vs [4,"x"]
    A2-03 (?<=\u{1F600}{3})x/u                     null      vs [6,"x"]
    A2-08 (?<=a\u{1F600}{2}b)x/u                   null      vs [6,"x"]
    A2-11 (?<=(\u{1F600}{2}))x/u                   null      vs [4,"x",pair]
    A2-12 (?<!\u{1F600}{2})x/u   on two pairs     [4,"x"]   vs null        FALSE POSITIVE
    A3-01 (?<=\uD83D)/u          on <emoji>       [1,""]    vs null        (bug 4 in the commit)
    A3-05 (?<=[\uDE00])x/u       on <emoji>x      [2,"x"]   vs null        FALSE POSITIVE
    A3-08 (?<=^[\s\S])x/u        on <emoji>x      null      vs [2,"x"]
    A4-01 (?<=$.*)/su            on <emoji2>      [1,""]    vs [2,""]       (bug 3 in the commit)
    A4-02 (?<=$.*)/su            on a<emoji2>     [2,""]    vs [3,""]       end reported as length-1
    A5-43 (?<=a|bc)x/            on bcx           null      vs [2,"x"]      our ALT06/ALT07 family
    B1-01..B1-04 the C3 oracle in four spellings  null      vs [3,"b","a"]
Reading: **every one of the 25 is a backward-path failure.** The class/atom path, the fixed-count
path, the surrogate-half path, the end-anchor path and the alternation path are each wrong, while
the general 45-case lookbehind suite passes 44 - which says the defect is concentrated in the
non-BMP handling of each backward helper, exactly as the commit message describes.

### The 67 divergences decompose into exactly three root causes
* **F1 - a sticky lastIndex inside a pair is not mapped through the code point list.** L1-01/02/05/
  06/07 diverge; V8 maps li=1 on a pair back to the code point at 0 ([0,"<emoji>"]) and this build
  starts at 1 with a bare trail.
* **F2 - the backward class/atom path walks a pair as TWO code units.** D1-04/D1-05 still return
  [2,"b"] where the spec answer is null.
* **F3 - the forward /u scan enters pair interiors and reports a match one unit early.** C1 (14 of 20
  diverge), the whole B2/B3/B4 family, and half of L1. F3 IS NOT ONE OF THE FOUR BUGS 956f6fb LISTS
  - those are all backward-path bugs, and the commit only rewrote the backward implementations.
  F3 is therefore not fixed by that commit, and the post-fix readCodePoint in the same patch still
  returns errorCodePoint for a forward read of a trail half, so main cannot produce a match at a
  pair interior. This build's forward read does not reject the trail half: that missing guard is F3.
* F3 forensics, answered by the data: C1-04 (`^` anchored) returns null while C1-05 (`$` anchored)
  matches at 1, so the scan really does try index 1 - the reported index is not a mis-report of a
  match that started at 0.
* The end-anchor arithmetic is its own shape of the same family: A4-01/A4-02 report the match end as
  length-1 whenever the last unit is a trail.

### Killed hypothesis (recorded so it is not retried)
The forward errorCodePoint corruption path - a forward backreference whose capture begins on a trail
half returning false with the position left advanced by matchSize - is **not reachable in this
build**. B2-01 `/(\uDE00)\1/u` on <emoji><trail> matched, with the capture recorded starting on the
trail half, so this build's reread does not return errorCodePoint there. The B family's divergences
are all F3 and nothing else. The unrestored-exit reading of the patch text remains true for the
September 2026 source; it does not describe fw 14.00.

### And the wall again, measured
* **0 cases** in the N2/N3/N4/N5/N8 family: no foreign code unit, no inverted range, no
  out-of-range index, no matched text disagreeing with its own index.
* **0** timing anomalies (N14), **0** nondeterminism (N6), **0** structural DRIFT.
* Four DRIFT lines (D1-01, D1-02, D1-03, D1-12) and two more (D1-09, D1-10) were **probe authoring
  errors, not engine changes**: the sticky controls never had lastIndex set (c() did not), and
  D1-09/D1-10/D1-12 had the wrong pattern reconstructed from the old page. V8 agrees with the new
  measurements in each case. All six are corrected in v2 below.
* Values that did NOT move between pages: D1-04, D1-05, D1-07, D1-08, D1-11, and the whole A/B/C
  body of the page, so the 09:33 run is comparable with 08:56 and 09:10.

### lb_u_probe.html revised to v2 (41,904 bytes, 251 cases)
Same five sections plus:
* the four mis-authored controls corrected (cSticky, real patterns), D1-12's expected value set to
  the measured `[]` (V8 agrees - its old `[1,2]` came from a different helper in the old page);
* **SECTION W, 64 cases**, pushing the three live bugs to a boundary rather than adding more
  spellings of them:
  W1 (20) end-anchored backward patterns over astral, lone-lead and lone-trail endings, hunting for a
  reported end outside [0,length]; the end-anchor arithmetic already reports length-1, so the
  question is whether it can be pushed to length-2 or past 0;
  W2 (12) boundary index pushes, including zero-width matches at the pair start, the pair end and
  the string end, and a capture of the unit after the trail;
  W3 (20) F3 driven all the way to the end: the trail as a start, a star/bounded/lazy tail and an end
  anchor, with captures recorded along the way;
  W4 (12) captures recorded at a boundary and then resolved through a backreference, including
  backrefs to a capture that ends at the string end and to a mid-pair capture inside a lookbehind.
V8 dry run: 235 CASE lines, 0 mismatches, all five SELFTEST detectors firing, no THREW. Reference
saved as lb_u2_v8_reference.txt. lb_u_v8_reference.txt is left alone - it is the reference the 09:33
run was diffed against.
## 09:46 HARDWARE RUN of lb_u_probe v2 (251 cases) - replication, and the boundary push

Complete: **235 of 235 case labels present, 0 missing**, 94 divergences.
**The 25 authoritative failures replicated exactly** - same labels, same values, thirteen minutes
apart. That makes them deterministic and reportable rather than lucky.
**0 memory-safety oracles again** (no N2/N3/N4/N5/N8), **0 timing anomalies**, and **0 DRIFT**: the
six controls that were mis-authored for the 09:33 run were corrected in v2 and every one of them
reproduced its measured value byte for byte, so the correction worked.

### Section W, group by group
* **W1 end-anchor arithmetic: 3 divergences, all in bounds.** The end is reported as length-1 when a
  pair sits at the end (W1-01 `[1,""]` vs `[2,""]`, W1-02 `[3,""]` vs `[4,""]`) but it never reaches
  length-2 and never goes below 0, so **the hunt for an out-of-range end failed**. W1-18
  `(?<=\u{1F600}{2})$/u` returns null where a match is due (the fixed-count non-BMP bug again).
  W1-03/04/05/13/17/19/20 all agree with V8, so the arithmetic is only wrong when the pair is at the
  end - a lone lead or a lone trail is handled correctly.
* **W2: 2 divergences, both F3** - a zero-width lookahead at a pair interior (W2-02 `[1,""]`) and the
  end-anchored trail (W2-09 `[1,"\uDE00"]`).
* **W3: 19 of 20 diverge, and this is the run's most useful result.** F3 is not only a wrong start
  position: from a mid-pair start the forward reader stops doing code point arithmetic and hands out
  RAW CODE UNITS, so every atom after the start works in unit space. W3-15 is the cleanest proof -
  `/\uDE00.$/u` on a pair followed by a lone lead returned `[1,"\uDE00\uD83D"]`, the dot consuming
  the LEAD of the next pair as a standalone character. W3-02 returned a match whose text starts
  mid-pair and contains a whole pair. Everything still inside the string.
* **W4 captures at a boundary: 3 divergences, all F3 shapes.** W4-04/06/08/09/10/11/12 agree with V8
  exactly, so the backreference machinery is correct once the position is legal - there is still no
  backreference-specific corruption. Note W4-10, the C3 shape WITH an extra capture around `\1*`,
  matches on hardware while B1-01..B1-04, with `\1*` directly inside the lookbehind, return null:
  the C3 loss depends on that exact spelling.

### THE WALL, RESTATED AFTER FIVE RUNS
94 wrong answers, 0 out-of-bounds reads, 0 inverted ranges, 0 foreign code units, 0 spins, 0
nondeterminism. Every divergence is F1, F2 or F3, and all three are bounded: the engine produces
illegal positions and then reads them correctly.

## lb_u_probe.html v3 - SECTION Z, the first test aimed at index == length
The trail of the last pair in a subject sits at length-1, so asking the pattern for one more unit is
a read at `m_input[length]` exactly - the read that only `ASSERT(index < length)` in readCodePoint
guards, and that assert is compiled out in release. The subjects all end in a complete pair, so the
spec answer for every Z pattern is null: a trail half is not a code point a /u pattern may match, and
there is nothing after it to match.
* **Z1 (20)** one more unit required - classes, dots, captures, lookaheads, word boundaries, fixed
  counts, both on `x+pair` and on a bare pair.
* **Z2 (10)** two units past the end.
* **Z3 (12)** backward walks that start at the very end with a pair sitting there.
* **Z4 (12)** quantifiers and captures that re-record a position at the end.
51 of the 54 are null on V8; Z3-04, Z3-10 and Z3-12 are spec-correct zero-width matches kept as
controls. Probe is now **301 cases / 47,680 bytes**; V8 dry run 0 mismatches, all five SELFTEST
detectors fire, no THREW. Reference `lb_u3_v8_reference.txt`.
If the guards hold, Z is a clean negative and the wall is real for this bug family. If they do not,
the oracles that fire will be N2 (a code unit that is not in the input = a genuine out-of-bounds
read), N5/N8 (a range or text the string cannot account for), N6/N7 (nondeterminism or a spin) or a
crash reported as THREW.

## Server fix made before this run - why a click in the guide showed no WebKit
The guide's own links point at Sony WEB PAGES. `www.playstation.com` fell through to BLOCK_MARKERS
and got NXDOMAIN, so a click inside the guide had no page to load at all - exactly the reported
symptom. `run_dns` now calls `is_guide(dom)`, which serves our IP for the manual AND for web-page
hosts (first label in www / support / manuals / document / help, name containing 'playstation').
Anything Sony runs as an API, store, CDN, update or telemetry host keeps its own first label and is
still blocked. Verified against 18 hostnames, then verified live against the running server:
`www.playstation.com` -> 192.168.137.1, `support.playstation.com` -> 192.168.137.1,
`feature.api.playstation.com` -> NXDOMAIN, `ps5.np.playstation.net` -> NXDOMAIN, `example.com` ->
forwarded. The saved cert already covers `*.playstation.com`, so no TLS problem. `[PAGE]` log lines
now carry the requested Host header so the next click is unambiguous.
ASCEND was shut down after the report, as asked: no listeners on 80/443/8765, nothing on
192.168.137.1:53, no python process left running.
## 09:52 HARDWARE RUN of lb_u_probe v3 (301 cases) - SECTION Z answers its question

The navigation came in as `[PAGE] 192.168.137.102 loaded lb_u_probe.html host=www.playstation.com`
- the host that was NXDOMAIN'd before the DNS fix, so the fix is what made this cycle possible.

Complete to **285 of 289 labels**: four POSTs (A5-04, A5-05, A5-08, A5-36) were dropped by the
single-threaded server during the burst - the page fires every POST without awaiting. All four were
measured in the 09:46 run and matched V8 there, so nothing is left unresolved.

### THE ANSWER: no read past the end of the string
**Zero cases in the memory-safety family again** - no N2, no N3, no N4, no N5, no N8. All ten Z2
cases (two units past the end) return null on hardware exactly as on V8; so do Z1-01..09, Z1-13 and
Z1-15..20. The forward bounds guards - the CheckInput terms the bytecode emits ahead of each atom -
hold even when the matcher has been entered at an illegal mid-pair position. Z1-15/Z1-16 ask for one
more unit with the pair at the very end of a two-unit subject, i.e. a read at m_input[length], and
both return null.

### What Z did find: 16 divergences, all three known bugs, all in bounds
* Z1-10, Z1-12, Z1-14 and the whole Z4 group (Z4-02, Z4-05..08, Z4-10..12) are F3 - a match at the
  trail of a pair, `[1,"\uDE00"]`-shaped, where the spec answer is null.
* Z3-01/Z3-02 (the F2 prefix at the end) return `[3,""]` and Z3-08/Z3-11 return `[2,""]` - the
  backward class path again.
* Z3-12 returns null where a match is due - the fixed-count non-BMP loss (the A2 family).
Every value is inside the string. No inverted range, no range outside [0,length], no code unit that
is not in the input, no nondeterminism, no spin.

### Replication, third time
**The 25 authoritative failures reproduced byte-identically for the third run** (09:33, 09:46,
09:52) - same labels, same values, 13 and 19 minutes apart. Total divergences 110 of 289 (the 94 of
the v2 run plus the 16 new Z ones).

## CONCLUSION AFTER SIX HARDWARE PROBES
The Yarr interpreter-only lookbehind family on fw 14.00 is now fully mapped: 25 of Apple's own 102
regression cases still fail, and every divergence in ~1,300 hardware cases decomposes into exactly
three root causes - F1 (a sticky lastIndex inside a pair is not mapped through the code point list),
F2 (the backward class/atom path walks a pair as two code units) and F3 (the forward /u scan enters
pair interiors, and after a mid-pair start the forward reader hands out raw code units, so a pair's
lead can be consumed as a standalone character - W3-15). All three are deterministic, reproducible
and precisely characterised, and all three produce wrong answers, false positives and ill-formed
strings.

**They have produced no memory-safety primitive.** Across six probes: zero inverted capture ranges,
zero ranges outside [0,length], zero foreign code units, zero nondeterminism, zero spins, and no
read at or past m_input[length] even when the pattern asks for units that do not exist. The one
unchecked read in the family, `reread(matchBegin + i)` guarded only by a release-compiled-out
ASSERT, still requires a capture with start > end, and nothing in the whole space has produced one.
Two hypotheses were killed by data along the way (the forward errorCodePoint position corruption of
C3, and an out-of-range end from the end-anchor arithmetic), which is the useful half of the result:
the boundary of this bug family is now known rather than assumed.

The honest reading: **stage 1 is not reachable by continuing to mine this family.** Further spellings
of F1/F2/F3 would add divergences, not primitives. The remaining value in the work is that F3 is a
forward-path spec violation that is NOT one of the four bugs Apple fixed in 956f6fb - it is a
reportable engine bug on its own, with a two-line reproducer and a build fingerprint.

================================================================================
## RUN ov_probe v1 - HARDWARE RESULT: the console died of memory exhaustion, and
## the log names the exact case. (2026-10-08, 09:59-10:00)
================================================================================

### What the console showed

White screen, then the console's own error: **"there is not enough free system
memory"**. That is the console browser's WebContent process hitting the system
memory ceiling, not an engine fault page.

### What the log says (ascend_raw.log, four page loads at 09:59:13, 09:59:22,
### 09:59:33, 10:00:14)

The `TRY`/`OK` protocol did exactly the job it was built for. In the last run
the stream ends:

```
10:00:14  TRY A-01        <- A-01..A-06 all return BOMB ... OK
10:00:15  TRY A-07        <- and then NOTHING, ever (log mtime 10:00:15)
```

**`TRY A-07` with no `OK A-07`.** A-07 was `cvs(16384,16384)`:
16384 x 16384 x 4 = **1,073,741,824 bytes = exactly 1 GiB**.

It is not a crash inside the arithmetic. In the three earlier runs of the same
page the same case came back:

```
RUN 1  09:59   BOMB A-07 status=ok SLOW ms=4622 0
RUN 2  09:59   BOMB A-07 status=ok SLOW ms=4805 0
RUN 3  09:59   BOMB A-07 status=ok SLOW ms=3355 0
RUN 4  10:00   TRY A-07  ... (nothing)
```

So the engine **really does back a 1 GiB canvas** (3.3-4.8 s of genuine work),
those backing stores were still resident when the next page load asked for
another one, and at that point the console's WebContent process died. **The
out-of-memory condition was caused by our own probe's legitimate 1 GiB
allocation, not by a bug in the engine.**

### The arithmetic result that A-01..A-06 already delivered

| case | request | logical | bytes if taken literally | observed |
|------|---------|---------|--------------------------|----------|
| A-01 | `65536x65536`    | 4,294,967,296 px | 17.18 GiB | `ok ms=0..2 px=0` - refused, no backing store |
| A-02 | `46341x46341`    | 2,147,488,281 px | 8.59 GiB  | `ok ms=0 px=0` - refused |
| A-03 | `32768x65536`    | 2,147,483,648 px (= exactly 2^31 px) | 8.59 GiB | `ok ms=1 px=0` - refused |
| A-04 | `65536x32768`    | 2,147,483,648 px | 8.59 GiB  | `ok ms=0..1 px=0` - refused |
| A-05 | `23170x23170`    | 536,848,900 px   | 2.147 GiB | `ok ms=0 px=0` - refused (just under 2^31 BYTES) |
| A-06 | `8192x8192`      | 67,108,864 px    | 256 MiB   | `ok ms=87..98` - **allocated** (positive control) |
| A-07 | `16384x16384`    | 268,435,456 px   | 1 GiB     | `ok SLOW ms=3355..4805` - **allocated** |

Read together: the canvas buffer size arithmetic is computed in wide arithmetic
and **refused** everywhere near or past 2^31 - at 2^31 px exactly, just under it
by bytes, and just over it by pixels. There is no evidence of an int32 overflow
producing a *small* allocation, which is the precondition for the single-call
out-of-bounds write this probe was built to find. **The canvas size-overflow
hypothesis is a negative result with data.**

The acceptance ceiling sits between 1 GiB (taken) and 2.147 GiB (refused).

### And a real, reproducible platform-level finding (separate from stage 1)

A web page can make the console's browser allocate a **1 GiB canvas** (3.3-4.8 s
of blocking work) and the browser imposes no per-page cap that prevents two of
them: doing it twice across page loads **kills the WebContent process and
replaces the page with "there is not enough free system memory"**. That is a
denial of service on the console browser from web content - not a memory-safety
primitive, and not what stage 1 needs, but it reproduces and it is user-visible.

================================================================================
## ov_probe v2 - rebuilt so an out-of-memory kill cannot cost us the run
================================================================================

Changes, all driven by the v1 failure above:

1. **The main summary is posted BEFORE any heavy ask.** Sections SELFTEST, A, B,
   C, D, E, F now end with `MAIN SUMMARY` and
   `ov_probe LIGHT SECTIONS COMPLETE - heavy group H starts now`. Whatever
   happens afterwards, the light results are already on the wire.
2. **A-07 no longer allocates 1 GiB.** It is now `cvs(46340,46340)` =
   2,147,395,600 px, the just-UNDER-2^31 twin of A-02 (which is just over), and
   it is cheap: nothing is allocated because the size is refused. A-06
   (256 MiB, allocated, 88 ms) stays as the positive control.
3. **New section H runs last** and is where the real allocations live: H-01
   `16384x16384` = 1 GiB (the measured ceiling), H-02 `20000x20000` = 1.6 GB (does
   the cap sit between the two?), then the Buffer/string asks as a table.
4. **Every heavy case announces its request first** with a `MEMREQ <id> asks for
   N MiB (N bytes) - what` line, so the log shows the asked-for size and not
   just the case id.
5. **Every heavy case releases its backing store and yields 500 ms before the
   next one** (`c.width=0; c.height=0` after the canvas work). Stacking two
   1 GiB canvases with no release is precisely what killed run 4.
6. H-02 (`20000x20000` = 1,600,000,000 bytes) maps the cap: 1 GiB is taken,
   1.6 GB is the next question.

### v2 verification (offline, on the reference engine)

* 27,788 bytes, 0 backticks, 0 CR, 0 non-ASCII bytes, extracted script passes
  `node --check`.
* Dry run: 319 messages, **94 cases, TRY/OK 94/94 balanced, 0 corruption, 0 error
  lines, `_done` posted**, all three SELFTEST checks pass.
* Marker lines in the dry run: `MAIN SUMMARY ... 84 cases` (posted before the
  heavy group), `MEMREQ` x 10, `FINAL SUMMARY ... 94 cases`, `ov_probe DONE`.
* **Served and confirmed:** the running ASCEND server returns the v2 bytes over
  HTTPS on both `www.playstation.com` and `manuals.playstation.net`
  (200 / 27,788 / md5 c4ec296e825e05aa99db72f917b18d57), containing the new
  `MEMREQ` and `LIGHT SECTIONS COMPLETE` markers. No server change was needed -
  `PAGE` is still `ov_probe.html`.

### One caveat to carry into the next run

In the dry run `new Uint8Array(0x100000000)` (4 GiB) and
`new ArrayBuffer(0x7FFFFFFF)` (2 GiB) both **succeed** on the reference engine,
because a fresh ArrayBuffer is lazily zeroed - success does not mean 4 GiB of
physical memory was touched. Only the canvas cases fault pages in. So a `status=ok`
on a G case is weak evidence unless the pages were written; the canvas cases
(G/H-01) remain the only honest large-allocation test in this probe.

### Recovery note

After an out-of-memory kill the console's browser needs the page reloaded (the
WebContent process restarts). v2 is already installed, so a plain reload of the
guide serves the fixed page.

================================================================================
## RUN ov_probe v2 ON HARDWARE (2026-10-08, 10:06) - 96 light cases, ZERO heap
## corruption, and the heavy group never got to run at all
================================================================================

### The light sections completed, and the result is a clean negative

The console ran the whole light portion and posted, three times:

```
[WIN] SUMMARY: 96 cases, 0 heap-corruption, 24 threw, 0 slow
```

96 cases is exactly the light census on a DOM engine: A(16) + B(16) + C(20) +
D(20) + E(12) + F(12). So every light case ran to completion.

* **0 heap-corruption** - the sentinel spray (24 x 2048 bytes, re-verified after
  every case) never changed. No out-of-bounds write was detected in any of the
  96 cases.
* **24 threw** - the safe outcome: RangeError / TypeError / IndexSizeError from
  the engine's own parameter checks.
* **0 slow** - nothing blocked.

### Per-case summary of the light sections

| group | what it attacks | outcome |
|-------|-----------------|---------|
| A (16) | canvas buffer size arithmetic | every dimension accepted (`c.width` reports what we asked, even `2147483647x2147483647`), allocation refused from 2.147 GiB up; only the 256 MiB case actually allocates (89 ms) |
| B (16) | ImageData allocation + dirty-rect math | 5 x RangeError, 3 x TypeError/InvalidStateError, 1 x IndexSizeError, 7 x accepted with sane values |
| C (20) | canvas filters, gradients, geometry at extreme parameters | 17 accepted, 3 x TypeError; all results finite |
| D (20) | the full SVG filter set at 1e9 .. 1e38 | **all 20 accepted**, each returning `40x40` in about 1 ms, no throw, no corruption |
| E (12) | createImageBitmap resize/crop arithmetic | mixed: some accepted, some InvalidStateError, some TypeError |
| F (12) | Intl formatting (DurationFormat, NumberFormat, DateTimeFormat) | 6 x RangeError, 6 x accepted with finite output |

### The one real divergence class: Intl accepts what the reference engine rejects

The reference engine (V8/Node) throws `RangeError` on exactly the two cases the
PS5 formats:

```
F-01  Intl.DurationFormat('en',{style:'long'}).format({seconds:1e21})
      PS5: "1,000,000,000,000,000,000,000 seconds"
      ref: THREW:RangeError

F-02  Intl.DurationFormat('en',{style:'digital'}).format({seconds:Number.MAX_VALUE})
      PS5: "0:00:179,769,313,486,231,570,000,000,000,000,000,000,000,000..."
      ref: THREW:RangeError
```

Every other F case agrees exactly (F-09 -> 15, F-10 -> 9/13/275760, F-11 -> ok,
F-12 -> 1) and F-03/F-04/F-05/F-07/F-08 throw RangeError on both. This is an ICU
version / clamping difference - the engine expands an absurd duration instead of
rejecting it. The outputs are finite digit strings produced by a bounded
conversion, so this is a behaviour difference, **not** a memory-safety signal.

Note the A/B/C/D/E status divergences in a naive diff are entirely an artefact:
the dry-run harness has no DOM, so every DOM case there reports THREW:TypeError.
Only the F group is a like-for-like comparison, and only F-01/F-02 differ.

### Why the heavy group never ran, and the crash loop it exposed

`grep 'BOMB G-'` across the ENTIRE log returns **zero**. No byte-count case has
ever executed on hardware. In the v2 window the log shows **twelve page loads**,
three of them live at the same moment (10:06:32 / 10:06:39 / 10:06:43), and each
posted `TRY H-01` with no `OK H-01`. The 1 GiB canvas kills the renderer; the
console replaces the page with "there is not enough free system memory"; the
browser then reloads the page, which tries again - an unwinnable loop, with
concurrent loads stacking 1 GiB requests on top of each other. In v1 the same
1 GiB canvas SUCCEEDED three times when it was the only load doing it
(`ok SLOW ms=3355 / 4622 / 4805`) and killed run 4 when a previous one was still
resident. So: the allocation is real, the console's ceiling is real, and the
result depends on how many copies are live at once.

## ov_probe v3 - the heavy group is now OPT-IN, so a plain load cannot crash

1. **`?heavy=1` gate.** The heavy group runs only when `location.search`
   contains `heavy=1`. A plain load (the guide click) runs the light sections, posts
   the summary and stops, with no multi-GB request anywhere.
2. **A clickable link, no URL typing.** At the end of a light run the page adds a
   green anchor `?heavy=1` to the document, which the console browser can follow
   with the controller. (`document.createElement` + `appendChild`, guarded by
   `HAS_DOM`, so the dry run is unaffected.)
3. **Order inside the heavy group is by hypothesis value, not by size.** The
   byte-count boundary cases run FIRST - `G-02` (2^31-1 bytes, the 32-bit
   boundary), `G-03` (2^32 bytes exactly - a byte count that overflows a uint32 to
   ZERO), `G-05` (2^31-1 string units) - and the canvas controls run LAST (`H-01`
   1 GiB, `H-02` 1.6 GB), because the canvas is the one measured to kill the
   renderer. If the console dies, it dies after the interesting data is already on
   the wire.
4. **The E-case labelling bug is fixed.** Every E case used to post as just `E-`
   (`id=cases[i][0].slice(0,2)`), so the 12 async cases were indistinguishable in
   the log. Each now carries its own id (`E-01` ... `E-12`).

### v3 verification (offline, both modes)

* 30,182 bytes, 0 backticks, 0 CR, 0 non-ASCII bytes, extracted script passes
  `node --check`. (The first cut of the gate left an unclosed brace; `node --check`
  caught it before anything was installed - recorded here because that is the
  check doing its job.)
* **Default load:** 84 cases (96 minus the 12 DOM-only E cases), `TRY`/`OK`
  84/84 balanced, **0 MEMREQ lines** (heavy group provably skipped),
  0 corruption, 0 errors, `_done` posted, marker reads
  `heavy group SKIPPED on this load (no ?heavy=1)`.
* **`?heavy=1` load:** 94 cases, `TRY`/`OK` 94/94 balanced, **10 MEMREQ lines**,
  heavy order verified as G-02, G-03, G-05, G-04, G-01, G-09, G-10, G-07, G-08,
  G-06, 0 corruption, 0 errors, `_done` posted.
* **Served:** the running server returns the v3 bytes on both
  `www.playstation.com` and `manuals.playstation.net` (200 / 30,182 /
  md5 cf93447d89ef0afb2c205b7f88bc5304), with the query string preserved by the
  browser (the server strips it when resolving the file, `location.search` keeps
  it), and the new gate + link markers present in the served bytes.

### The honest state of the size-arithmetic route

The canvas / ImageData / SVG-filter / Intl surfaces, 96 cases plus the 106-case
v1 partial run: no memory-safety signal at all, and the engine refuses every size
near 2^31. What has never been tested on hardware is the one case where a byte
count crosses 2^32 exactly - and that is precisely the first thing the gated
heavy group now runs.

================================================================================
## THE ?heavy=1 CRASH LOOP (2026-10-08, 10:15-10:16) and ov_probe v4
================================================================================

### What the user saw

"it says that memory thing so i press ok to try reload it" - the console browser
was back to "there is not enough free system memory", and pressing OK reloads the
page.

### Why it looped - the mechanism, from the log

The 10:15-10:16 window contains SEVEN page loads in about 25 seconds
(10:15:44, 10:15:54, 10:15:58, 10:16:04, 10:16:06, 10:16:09, 10:16:10). The
sequence that matters:

```
10:15:47  ov_probe DONE
10:15:48  SUMMARY: 96 cases, 0 heap-corruption, 24 threw, 0 slow
10:15:48  LIGHT SECTIONS COMPLETE - heavy group SKIPPED on this load (no ?heavy=1)
10:16:00  TRY G-02                      <- heavy group started
10:16:04  LIGHT SECTIONS COMPLETE - heavy group SKIPPED on this load (no ?heavy=1)
10:16:07  HEAVY TAIL ENABLED by ?heavy=1
```

The gate worked exactly as built: the plain load ran 96 cases, posted the summary
and stopped, and printed that the heavy group was SKIPPED. Then the user followed
the green link, which navigates to `?heavy=1` - and **a load that crashes leaves
that URL in the address bar, so the console's OK-and-reload re-requested the heavy
page and killed itself again.** That is the loop, and it is a design fault in my
gate, not a fault in the console.

### The finding inside the failure: **TRY G-02, and nothing after it**

`G-02` is `new ArrayBuffer(0x7FFFFFFF)` - 2,147,483,647 bytes, the 32-bit boundary
itself, and the FIRST case of the heavy group by design. Its line arrived with no
`MEMREQ` (which is emitted in the same synchronous tick, immediately after `TRY`),
no `BOMB` and no `OK`. So the console died *at* that request.

Honest caveat on that inference: the single-threaded server DOES drop result POSTs
under a burst - four were lost in the v1 era, and F-06, F-11 and D-20 lost their
lines in the v2 run - so the missing `MEMREQ` on its own is not proof of death at
that instant. What is not in doubt is the other half: no `BOMB G-02` and no
`OK G-02` ever arrived, the heavy group produced no result at all, and the browser
was sitting on "there is not enough free system memory" immediately afterwards.
G-02 remains the case that took the browser down.

Read together with the canvas data this is coherent: this engine **commits** large
ArrayBuffer requests rather than refusing them. A 1 GiB canvas is survivable when
it is the only thing asking; 2 GiB is not. Conclusion: **the allocating form of the
2^31/2^32 boundary test is unreachable on a console we want to keep using** - the
test costs the browser every time.

## ov_probe v4

1. **The loop is closed at the source.** Before the heavy group runs, a marker is
   written (`ov_probe_heavy_attempted`) and any later load that requests `?heavy=1`
   WITHOUT `&again=1` refuses to run it again, saying so in the log. A reload of the
   crashed URL therefore cannot re-attempt it. Honest limitation: this depends on
   `localStorage` being usable in the console browser - the read and write are both
   wrapped in try/catch and degrade to "no marker", in which case the manual escape
   is to load a URL without a query string.
2. **The canvas controls need a second, separate opt-in.** `&canvas=1` adds H-01 /
   H-02 (the 1 GiB and 1.6 GB canvases). Without it the heavy group is the
   byte-count/string/blob cases only, and the log says so.
3. **New section J - the same boundary question, asked 20 ways that cannot
   allocate.** This is the real fix. `subarray`, `slice`, `copyWithin`, `fill`,
   `set`, `DataView` offsets, `ArrayBuffer.prototype.slice`, `Array` and `String`
   lengths, `repeat`, `Blob.slice`, `TextEncoder` output: every one of them either
   clamps the argument or throws, so the 2^31 / 2^32 arithmetic is exercised with
   no backing store at all. It runs in the LIGHT path, so a plain guide click now
   tests the boundary that the heavy group could never reach.

### v4 verification (offline)

* 34,595 bytes, 0 backticks, 0 non-ASCII, extracted script passes `node --check`.
* 20 J cases, no duplicate ids, all present exactly once.
* Default load: **104 cases, `TRY`/`OK` 104/104**, 0 `MEMREQ` lines (heavy group
  provably skipped), 0 corruption, 0 errors, `_done` posted. On hardware the light
  census becomes 96 + 20 = **116 cases**.
* Reference-engine values for section J, to compare against the console:
  ```
  J-01 16   J-02 0    J-03 16   J-04 16   J-05 16   J-06 16   J-07 16
  J-08 16   J-09 0    J-10 THREW:RangeError   J-11 THREW:RangeError
  J-12 THREW:RangeError   J-13 3   J-14 3   J-15 THREW:RangeError
  J-16 2147483647   J-17 THREW:RangeError   J-18 3   J-19 3   J-20 6
  ```
* Loop-breaker re-verified after the final edit: with the marker already set, a
  `?heavy=1` load runs 104 light cases, **0 MEMREQ lines**, and logs
  `HEAVY TAIL NOT RUN AGAIN`; `?heavy=1&again=1` re-arms it and the heavy group runs
  again (10 `MEMREQ` lines).
* Served: 200 / 34,595 / md5 4cd0f3cbedbdd0b02c96b1d5a2d3806c on both
  `www.playstation.com` and `manuals.playstation.net`, with the J-section and
  loop-breaker markers present in the served bytes.

### The safe instruction, given the loop

**Open the guide again (or press BACK) so the address has no `?heavy=1`.** The
plain page is now the complete light run - 116 cases including the whole boundary
section J - and it cannot take the browser down. The heavy group stays available
but opt-in, one-shot, and no longer on the reload path.

================================================================================
## SECTION J ON HARDWARE: THE 2^31 / 2^32 BOUNDARY IS CORRECT - 20 of 20
## (2026-10-08, loads between 10:22 and 10:25)
================================================================================

This is the clean, COMPLETE negative the size-arithmetic route needed. Every J
case ran on the console and every one matches the reference engine exactly:

```
J-01  PS5=ok 16                     ref=ok 16
J-02  PS5=ok 0                      ref=ok 0
J-03  PS5=ok 16                     ref=ok 16
J-04  PS5=ok 16                     ref=ok 16
J-05  PS5=ok 16                     ref=ok 16
J-06  PS5=ok 16                     ref=ok 16
J-07  PS5=ok 16                     ref=ok 16
J-08  PS5=ok 16                     ref=ok 16
J-09  PS5=ok 0                      ref=ok 0
J-10  PS5=THREW:RangeError          ref=THREW:RangeError
J-11  PS5=THREW:RangeError          ref=THREW:RangeError
J-12  PS5=THREW:RangeError          ref=THREW:RangeError
J-13  PS5=ok 3                      ref=ok 3
J-14  PS5=ok 3                      ref=ok 3
J-15  PS5=THREW:RangeError          ref=THREW:RangeError
J-16  PS5=ok 2147483647             ref=ok 2147483647
J-17  PS5=THREW:RangeError          ref=THREW:RangeError
J-18  PS5=ok 3                      ref=ok 3
J-19  PS5=ok 3                      ref=ok 3
J-20  PS5=ok 6                      ref=ok 6

identical to reference: 20   divergent: 0   not measured: 0
```

Reading: `subarray` / `slice` / `copyWithin` / `fill` / `ArrayBuffer.prototype.slice`
all CLAMP a 2^31 or 2^32 argument exactly as the spec requires; `DataView` with a
2^31 length or a negative offset, `set` with a 2^31 offset, `String.prototype.repeat`
with a 2^31 count and `new Array(2^32)` all throw RangeError; `new Array(2^31-1)` is
accepted. **No length or offset arithmetic overflows into a wrong small value
anywhere on this console, and nothing wrote outside anything.** Combined with the
canvas results (refused from 2.147 GiB up) and the 96 light cases with zero
sentinel damage, the size-arithmetic hypothesis is answered: negative, with data.

## WHY THE BROWSER KEPT DYING: G-02, three attempts, zero results

```
10:16:00  TRY G-02      (no MEMREQ, no BOMB, no OK - ever)
10:24:24  TRY G-02      (same)
10:24:29  TRY G-02      (same)

meanwhile, in the same sessions:
10:22:57  ov_probe DONE / FINAL SUMMARY
10:24:12  ov_probe DONE / MAIN SUMMARY / FINAL SUMMARY
10:24:28  MAIN SUMMARY
```

`G-02` was `new ArrayBuffer(0x7FFFFFFF)` - 2 GiB. Three attempts, three instant
deaths, while the light runs in the same window completed three times. The engine
**commits** what it is asked for instead of refusing it: a 2 GiB request does not
return an error, it takes the browser with it. Every crash the user reported was a
`?heavy=1` load dying at that single case about one second into the heavy group.

### The storage loop-breaker does not work on this browser

The 10:23:05 load logged `HEAVY TAIL ENABLED by ?heavy=1` - not `NOT RUN AGAIN` -
even though a marker had already been written by the 10:23:02 load. So
`localStorage` is not persisting in the console browser. **The loop-breaker cannot
be relied on, and protection has to be structural instead.**

## ov_probe v5 - no case may ask for more than the browser can give

1. **The fatal cases are deleted.** `G-02` (2 GiB ArrayBuffer) and `G-03`
   (4 GiB Uint8Array) are gone from the page; verified absent from the served
   bytes. Asking again for a size already measured as fatal teaches nothing.
2. **A ramp replaces them:** `G-11` 64 MiB, `G-12` 128 MiB, `G-13` 256 MiB,
   `G-14` 512 MiB ArrayBuffers, `G-15` a 512 MiB `Uint8Array` (the allocating view
   form), `G-16` a 64 MiB string - each announced with a `MEMREQ` line and each
   followed by a 500 ms yield. This measures how much the browser will actually
   hand out without ever asking for a size known to be fatal. The canvas stage
   (`&canvas=1`) now starts with `H-03` (a 256 MiB canvas) before the 1 GiB control.
3. **Every case now gives its backing store back.** A `releaseCvs()` runs at the
   end of every case in `bomb()`, in the E async loop and in the heavy path, and
   `cvs()` records the canvas it made. Previously only the heavy cases released,
   so each light run left a 256 MiB canvas waiting for the GC - and the user was
   reloading this page over and over, which stacked them.
4. **The light run's largest allocation drops from 256 MiB to 64 MiB** (`A-06` is
   now 4096x4096). The 256 MiB fact was already measured on hardware at 09:59
   (`A-06 status=ok ms=88`), so nothing is lost and the peak the light path needs
   falls by three quarters.

### v5 verification

* 36,290 bytes, 0 backticks, 0 non-ASCII, 0 CR, extracted script passes `node --check`.
* Default load: **104 cases, TRY/OK 104/104, 0 MEMREQ** (heavy group provably
  skipped), 0 corruption, 0 errors, `_done` posted.
* `?heavy=1` unseeded: 113 cases, TRY/OK 113/113, 9 MEMREQ lines, the whole ramp
  returning `ok` on the reference engine, 0 corruption, 0 errors, `_done` posted.
* `?heavy=1` with the marker set: heavy group blocked (0 MEMREQ).
* Served: 200 / 36,290 / md5 50781eb97a895d9f927fb7d181bdb682 on both
  `www.playstation.com` and `manuals.playstation.net`; the served bytes contain the
  ramp (`G-11`, `ramp step 4`, `releaseCvs`, section J) and contain **zero**
  references to `G-02` or `G-03` as cases.

### The instruction that ends the loop

**Load the guide with no query string.** The plain page is the safe one: 116 cases
(96 + 20 J), a 64 MiB peak, canvas released every case, and it cannot reach the
2 GiB request.

================================================================================
## "GOT TO PAGE 3 THEN A CRASH" - THE AMPLIFIER WAS THE GUIDE ITSELF
## (2026-10-08, 10:29-10:31) and the one-probe-per-client fix
================================================================================

### What the user reported and what the log shows

"got to page 3 then a crash". The log for 10:29:59 - 10:30:47 has SIX page loads
in 47 seconds (10:29:59, 10:30:09, 10:30:23, 10:30:42, 10:30:44, 10:30:46), light
runs completing three times (FINAL SUMMARY at 10:30:03, DONE + FINAL SUMMARY at
10:30:16, MAIN SUMMARY at 10:30:27) and then one run dying mid-light-section at
10:30:47, inside the E group.

Earlier in the same session the light page had completed reliably. The difference
is not the page - it is the CUMULATIVE count. The mechanism:

**DNS sends every playstation guide host to our server, and the server answers
every unknown path with PAGE.** So every page of the guide the user clicks through
is a fresh load of the probe, each with its own sentinel spray, its own canvas and
its own renderer-side bookkeeping, and the browser keeps the ones it has left in
its page cache. On the third or fourth navigation the accumulated pressure kills
the WebContent process - which is exactly where the crash lands, and exactly what
"page 3" means.

So the amplifier was never the probe's own case list. It was **our delivery
mechanism**: one guide navigation = one full probe run.

### The fix, in the server: serve the probe ONCE per client

`ps5_server.py` now keeps `PROBE_ONCE` keyed by client IP. The first request for
`PAGE` from a client is served normally; every later one gets `STUB_PAGE`, a
528-byte inert HTML document that says the probe already ran and how to re-arm it.
`/again` as a path, or `?again=1` as a query, bypasses the stub deliberately.

Verified live against the restarted server (PID 15808):

```
1) GET /                    -> 200, 36290 bytes, 8 probe markers
2) GET / (same client)      -> 200, 528 bytes, "ASCEND - probe already run"
3) GET /?again=1            -> 200, 36290 bytes  (re-armed)
4) GET /again               -> 200, 36290 bytes  (re-armed)
server log: [PAGE] 127.0.0.1 loaded ov_probe.html ...
            [STUB] 127.0.0.1 served the inert page - the probe already ran once (1x)
```

Consequences: a console clicking through the guide gets the probe exactly once and
then harmless 528-byte pages, so navigation can no longer accumulate anything; and
because the counter lives in the server process, restarting the server re-arms the
console. `ps5_server.py` compiles clean (`py_compile`), the pre-change file is kept
as `ps5_server.py.pre_stub_backup`, and no `__pycache__` is left behind.

### What this does NOT change

The page itself was already safe: 64 MiB peak canvas, released every case, spray
freed between cases, and the two fatal 2 GiB asks (G-02/G-03) deleted in v5. The
stub removes the last amplifier, which was the number of times the page could be
loaded at all.

================================================================================
## THE RAMP RAN ON HARDWARE - AND THE LAST CRASH WAS THE CANVAS STAGE
## (2026-10-08, 10:36) plus the cooldown that finally cannot be bypassed
================================================================================

### The ramp: every step the browser was asked for, it gave (and gave quickly)

Five complete heavy runs landed in the 10:36 window, and the ramp came back
identical every time:

| case | request | result on hardware |
|------|---------|--------------------|
| G-11 | ArrayBuffer 64 MiB      | `ok`, 4-16 ms |
| G-12 | ArrayBuffer 128 MiB     | `ok`, 8-21 ms |
| G-13 | ArrayBuffer 256 MiB     | `ok`, 16-39 ms |
| G-14 | ArrayBuffer 512 MiB     | `ok`, 33-79 ms |
| G-15 | Uint8Array 512 MiB      | `ok`, 32-34 ms |
| G-16 | string 64 MiB of units  | `ok`, 5-17 ms |
| H-03 | canvas 8192x8192 (256 MiB) | **`ok`, 39 ms, pixel readback 255** |

`H-03` is the most useful line in this probe's history: **`px=255` means the
allocation was written to and read back.** Every other large-allocation result in
this project only ever proved a *length*; this one proves real, usable, pixel-
addressable memory at 256 MiB, drawn into with `fillRect` and read back with
`getImageData`. The safe ceiling is therefore somewhere between 512 MiB (given, at
33-79 ms) and 2 GiB (fatal, G-02).

### The crash near the end of the run was H-01, and the URL asked for it

The user's URL carried `?heavy=1&canvas=1` - the link this page renders after a
heavy run. The log for that run:

```
LIGHT SECTIONS COMPLETE ... then the ramp, all ok
TRY H-03 / MEMREQ H-03 256 MiB / BOMB H-03 status=ok ms=39 8192x8192 px=255
TRY H-01 / MEMREQ H-01 1024 MiB - canvas 16384x16384   <- and that is the last line
```

So: light sections fine, ramp fine, 256 MiB canvas fine and drawn, and the 1 GiB
canvas takes the browser down. Same case that killed v1 run 4, the v2 loads and now
this run.

### Two fixes

1. **H-01 and H-02 are DELETED from the page**, for exactly the reason G-02 and
   G-03 were deleted: the case is measured fatal, repeatably, and there is nothing
   left to learn from it. The canvas stage is now a single 256 MiB `H-03` behind
   `&canvas=1`. Verified: the page contains exactly one `heavyCanvas(...)` call and
   it is `H-03`; `H-01` survives only inside a comment and one info string.
2. **The server serves the probe at most once per client per 45 seconds - a
   COOLDOWN, with nothing to bypass.** The first attempt (a counter plus an
   `?again=1` escape) failed for a reason worth recording: *the escape was carried
   in the URL*, so reloading the crashed URL bypassed the stub every single time.
   The console was served the full probe 5 times in 41 seconds and ran the whole
   heavy group each time. A cooldown cannot be defeated by a URL.

Verified live against the restarted server (PID 13636):

```
1st GET /            -> 200, 36144 bytes  (the probe)
2nd GET /            -> 200, 532 bytes    (resting page)
3rd GET /?again=1    -> 200, 532 bytes    (resting page - the bypass is gone)
4th GET /again       -> 200, 532 bytes    (resting page)
```

The stub says what it is: the probe is resting, one run per 45 s per console, and
the reason is that five runs in 41 seconds is what took the browser down.

### State after this

* Light census: 116 cases (96 + 20 J), 64 MiB peak canvas, every canvas released
  as its case ends.
* Heavy group: the 64/128/256/512 MiB ramp plus controls, all measured `ok`.
* Canvas stage: one 256 MiB canvas, measured `ok` and drawn.
* No case left in the page asks for a size that has ever killed this browser.

### 10:47 - the resting page gets a countdown, and a restart lesson

The console sat on the resting page for three reloads in a row (10:43:10, 10:44:03,
10:44:10, 10:44:14 - the server log shows 36s, 41s, 35s, 31s, 30s of cooldown left),
because a reload inside the 45 s window correctly gets the stub. The stub now
counts down out loud: "About N seconds left of the 45-second cooldown. After that,
load the guide once and the probe runs." Verified live: 1st GET -> probe 36144
bytes, 2nd GET -> resting page 547 bytes containing the countdown sentence.

Also worth writing down for the next restart: the BACKGROUND wrapper PID is not the
listener. Killing the wrapper left the real server (a python child) holding 80/443/
8765, and the new instance could not bind. Always kill the PID that `netstat` shows
next to the LISTENING line, not the one the launcher printed.

### 10:48 - the verified end state, after the crashes stopped

The cooldown and the deletion of the fatal cases together produced the first clean
stretch of the session. From the log, counting only the populated page (v5):

* **25 complete runs**: 21 at `116 cases, 0 heap-corruption, 29 threw, 0 slow`
  (light only), 3 at `125 cases` (light + the whole ramp), 1 at `126 cases`
  (light + ramp + the 256 MiB canvas). That is ~2,940 case executions on hardware.
* **29 threw** is the correct number, not a regression: 24 from the light census
  plus the 5 J cases that must throw (`J-10/11/12/15/17`).
* The heavy group, newest run: `G-11` 64 MiB ok 5 ms, `G-12` 128 MiB ok 8 ms,
  `G-13` 256 MiB ok 17 ms, `G-14` 512 MiB ok 32 ms, `G-15` 512 MiB view ok 33 ms,
  `G-16` 64 MiB string ok 5 ms, controls ok, and `H-03` 256 MiB canvas **ok 40 ms,
  px=255** - drawn and read back.
* The sentinel oracle never fired: `CORRUPTION after <case>` appears **0 times**,
  and the summary's `CORRUPTION CASES:` list appears **0 times**. Eighteen log lines
  do mention HEAP-CORRUPT; all eighteen are the explanatory line that every summary
  block prints ("Reading: HEAP-CORRUPT means a sentinel ArrayBuffer changed...").
  Checked precisely because a bare grep count of 18 looks alarming and is not.
* Server behaviour in the same window: probe served 10:47:32 and 10:48:19, with
  reloads at 10:47:44 / 10:47:51 / 10:48:05 / 10:48:11 / 10:48:34 / 10:48:35 all
  correctly given the resting page.

What this does and does not establish: the sentinel spray saw no linear overwrite
of a neighbouring allocation across ~2,940 executions, and no case produced an
out-of-range length or offset. It does NOT prove the absence of every bug class -
a use-after-free that writes into still-valid memory elsewhere, or a fault that
needs a particular allocation layout, would not show up in a linear sentinel sweep.

================================================================================
## SECTION K (WebAudio) AND SECTION L (WebGL) - the next surfaces, 2026-10-08 10:5x
================================================================================

Two closed families in and two new ones open. Sections K and L are added to the
SAME page and run in the LIGHT path, because every case in them either throws,
clamps, or asks for something the driver must refuse - none of them commits memory.

**K: WebAudio offline arithmetic, 17 cases.** `OfflineAudioContext` is used
deliberately: pure computation and memory, no audio device, no rendering, no user
gesture needed. Every case is a request the spec REQUIRES to be refused - zero
channels, negative or NaN length, sample rate 0 or 2^31-1, an out-of-range channel
index via `getChannelData(0x7FFFFFFF)`, `copyToChannel` / `copyFromChannel` with an
offset of 0x7FFFFFFF past the end of an 8-frame buffer, `start(0, 0x7FFFFFFF, 1e9)`
on a tiny buffer, `channelCount = 0x7FFFFFFF`, and AudioParam ramps to +-1e21. A
THREW is the expected answer; the finding is a case that does NOT throw. Nothing
asks for more than 8 frames of audio.

**L: WebGL validation before allocation, 12 cases.** The two potentially expensive
cases do not guess at a limit - they read the driver's own
`MAX_TEXTURE_SIZE` / `MAX_RENDERBUFFER_SIZE` and ask for ONE PAST it. It was four
times the limit in the first cut, and that was changed on review: a request beyond
the limit must be refused either way, so the extra size buys no information and
only enlarges the worst case if a port ever validates after allocating instead of
before it. The rest
are an offset of 0x7FFFFFFF into a tiny buffer (`bufferSubData`), a `drawArrays`
and a `drawElements` with a count of 0x7FFFFFFF and a draw offset of 0x7FFFFFFF,
`texImage2D` with -1 x -1, a `viewport` / `scissor` with 0x7FFFFFFF and -1, the one
bounded real allocation (a 64 MiB `bufferData`, then deleted), a 4x4 `readPixels`
control and a shader compile control. The console's own GL limits are logged before
any case runs, which is useful by itself.

Verified: 42,353 bytes, 0 backticks, 0 non-ASCII, 0 CR, `node --check` clean, ids
K-01..K-17 and L-01..L-12 with NO duplicate ids anywhere in the page, dry run
104/104 with 0 MEMREQ / 0 corruption / 0 errors / `_done`, and both new sections
skip cleanly in the harness (which has neither API) rather than reporting failures.
Installed and served: md5 353898e86d661c9d3f393bacb4a1a0fc, 200 / 42,353 on both
www.playstation.com and manuals.playstation.net, with the K-17, L-12 and
MAX_RENDERBUFFER_SIZE markers present in the served bytes.

Honest limitation: Node has neither `OfflineAudioContext` nor WebGL, so there is NO
reference-engine baseline for these 29 cases. The expectation for each is the
WEBIDL/spec requirement, written into the case itself. So the reading rules differ
from earlier sections: here a MATCH on an allowed value is not the signal - the
signals are (1) a case that does not throw where the spec says it must, (2) any
sentinel change, (3) the reported GL limits.

Light census on hardware was PREDICTED here as 96 + 20 (J) + 17 (K) + 12 (L) = 145.
The console proved that wrong within the hour: K and L do not execute, because this
engine exposes neither a WebGL context nor the OfflineAudioContext constructor. With
section M added the real hardware light census is 96 + 20 (J) + 8 (M) = 124 cases,
and the 29 cases of K and L are dead weight on this platform - kept in the page only
so the absence is re-proved on every run rather than asserted once.

Post-review re-verification of the L-08/L-09 change: `m*4` appears 0 times, `m+1,m+1`
appears twice, the only surviving "four times" is the sentence explaining why it is
not used, 0 backticks / 0 non-ASCII / 0 CR, 42,520 bytes, `node --check` clean,
0 duplicate ids, dry run still 104/104 with 0 corruption and 0 errors, and
master = installed = served at md5 d437ef00dffb9c503737ec12fbe72e6e (200 / 42,520)
with `m+1,m+1` present in the served bytes.

================================================================================
## THE TWO NEW SURFACES DO NOT EXIST ON THIS CONSOLE (2026-10-08, 10:57-10:58)
================================================================================

The K and L sections were installed and the console loaded the page three times.
The log answers for them immediately, and not in the way expected:

```
[info] no WebGL context in this engine: section L skipped      (x3)
[info] no OfflineAudioContext in this engine: section K skipped (x3)
```

`canvas.getContext('webgl')` returns **null** on fw 14.00, and the constructor
`OfflineAudioContext` is **not exposed at all**. So the summaries stayed at 116 /
125 / 126 cases: those cases never ran, because the APIs are not there. Two whole
C++ families - the GL driver stack and the offline audio graph - are closed by
ABSENCE rather than by testing. Precisely: what is proven absent is a WebGL context
from a page canvas and the `OfflineAudioContext` constructor; whether some other
audio entry point (`AudioContext`, a webkit-prefixed alias) exists was NOT tested by
that build, which is why M-02 tests it directly.

The run that did happen in that window completed cleanly:

```
[WIN] SUMMARY: 126 cases, 0 heap-corruption, 29 threw, 0 slow
... TRY H-03 / MEMREQ H-03 256 MiB / BOMB H-03 status=ok ms=38 8192x8192 px=255
... ov_probe DONE
```

## Section M added: stop guessing which surfaces exist, enumerate them

Eight cases, all cheap, each returning a compact list. Nothing allocates more than a
short string and nothing renders, plays or decodes. M-01 graphics (webgl2, webgpu,
OffscreenCanvas, ImageDecoder, VideoDecoder, VideoFrame); M-02 audio (AudioContext,
the webkit aliases, OfflineAudioContext, AudioBuffer, AudioWorkletNode); M-03 engine
(WebAssembly, compileStreaming, SharedArrayBuffer, Atomics, BigInt64Array,
structuredClone, CompressionStream, crypto.subtle); M-04 fonts and text (FontFace,
FontFaceSet, document.fonts, Intl.Segmenter, TextMetrics); M-05 and M-06 the decoder
question, answered by the engine itself - `canPlayType` and
`MediaSource.isTypeSupported` for H.264, H.265, AV1, VP9, MPEG-TS, AAC and Opus -
plus Worker, SharedWorker, serviceWorker, WebSocket, RTCPeerConnection; M-07 storage
(localStorage, sessionStorage, indexedDB, caches, navigator.storage, which also
documents the localStorage-in-console finding independently); M-08 machine facts
(UA, screen, hardwareConcurrency, deviceMemory).

## A self-inflicted ambiguity, found and removed

`tv()` originally reported a refused capability as `ERR:<name>`, and `ERR:` is the
page's UNCAUGHT-error channel - `window.onerror` emits `ERR:<msg>@<line>`. So the
very first dry run of section M reported one error line that was not an error: it
was M-06's *value*. Changed to `THREW:<name>`, matching the convention `bomb()`
already uses. Re-verified: 112 cases, 112/112 balanced, 0 corruption, **0 error
lines**, `_done` posted. Worth recording because a metric that cries wolf once is a
metric nobody trusts later.

================================================================================
## THE CAPABILITY CENSUS, ON HARDWARE (2026-10-08, 11:03) - what this browser
## actually exposes, and a correction to one of my own earlier conclusions
================================================================================

M-01 webgl2=undefined webgpu=undefined offscreenCanvas=undefined
      imageDecoder=undefined videoDecoder=undefined videoFrame=undefined
M-02 AudioContext=undefined webkitAudio=undefined OfflineAudioContext=undefined
      webkitOffline=undefined AudioBuffer=undefined AudioWorklet=undefined
M-03 WebAssembly=undefined wasmCompileStreaming=undefined
      SharedArrayBuffer=undefined Atomics=object BigInt64Array=function
      structuredClone=function compre[cut]
M-04 FontFace=function FontFaceSet=function documentFonts=object
      segmenter=function TextMetrics=function
M-05 mp4h264=probably mp4h265=probably mp4av1=probably webmvp9=probably
      mpegts= aac=probably opus=probably
M-06 MediaSource=function mse_mp4=true mse_av1=false Worker=function
      SharedWorker=function serviceWorker=undefined websocket=function rtc=undefined
M-07 localStorage=object sessionStorage=object indexedDB=undefined caches=object
      navigatorStorage=undefined
M-08 ua=Mozilla/5.0 (PlayStation; PlayStation 5/14.00) AppleWebKit/605.1.15
      (KHTML, like Gecko) Version/17.0 Safari/605.1.15 screen=1920x1080@1 cores=4

### What is ABSENT - and this is the headline

No WebGL2/WebGPU/OffscreenCanvas/WebCodecs/ImageDecoder. No WebAudio at all - not
even `AudioContext`, so the earlier "no OfflineAudioContext" finding is narrower
than the truth: the whole audio graph is gone. And the largest omission of all:
**`WebAssembly` is undefined.** No WASM, no shared memory, no `SharedArrayBuffer`,
no service worker, no indexedDB, no WebRTC.

That removes most of the native attack surface a modern browser normally presents.
Whoever built this browser switched it off deliberately rather than leaving it
exposed, and it is consistent with a console that has never had a public web
browser jailbreak.

### What is PRESENT - therefore what is left to attack

`FontFace` + `FontFaceSet` + `document.fonts` (the font parser IS reachable),
`Intl.Segmenter`, canvas 2D and SVG filters (already probed, clean), a media element
that answers `probably` for **H.264, H.265, AV1, VP9, AAC and Opus**, MediaSource
(mp4/H.264 admitted, AV1 refused at MSE level), Worker/SharedWorker/WebSocket,
localStorage/sessionStorage/caches, structuredClone, BigInt64Array, Atomics.

Ranked by remaining value: (1) font parsing, (2) image decoding through `<img>` and
`createImageBitmap` (AVIF/HEIC/WebP - note M-10 asks whether createImageBitmap even
exists, since ImageDecoder does not), (3) media demux/decode through `<video>`, where
H.265 and AV1 are both admitted, (4) compression streams (M-09), (5) SVG/canvas, done.

### Correction to an earlier conclusion in this record

On 10:23 I wrote that localStorage "is not persisting in the console browser",
inferred from one `HEAVY TAIL ENABLED` line. The census contradicts the premise:
`localStorage=object` and `sessionStorage=object` both exist. The 10:23:05 load was
the FIRST load of the v4 page, so no marker had been written yet and ENABLED was the
CORRECT answer, not evidence of a storage failure. The inference was wrong. The
cooldown makes it operationally moot, but the record should not carry a claim its
own later measurement disproves.

### Why M-09 and M-10 were added

The page caps an emitted line at 450 characters and the SERVER caps a logged result
at 400, so M-03 was cut mid-word at "compre" and M-08 lost its tail. Rather than
raise either cap, the missing items got their own short cases: M-09 (CompressionStream,
DecompressionStream, crypto.subtle) and M-10 (createImageBitmap, Image,
document.fonts.size, FontFace.prototype.load). Verified: 114 cases, TRY/OK 114/114,
0 corruption, 0 error lines, `_done`; 48,824 bytes, 0 backticks / 0 non-ASCII / 0 CR,
node --check clean, 0 duplicate ids; master = installed = served at
md5 973cec01fbc134e9e82b510fbe25918e (200 / 48,824).

================================================================================
## M-09 / M-10 LAND, AND SECTION N IS BUILT ON WHAT THEY SAY (2026-10-08, 11:07)
================================================================================

```
BOMB M-09 CompressionStream=function DecompressionStream=function cryptoSubtle=object
BOMB M-10 createImageBitmap=function Image=function fonts=0 FontFaceLoad=function
```

So the two richest remaining surfaces are BOTH open: the font parser
(`FontFace.prototype.load` is a function, `document.fonts` exists) and the image
decoders (`Image`, `createImageBitmap`), plus a third, compression
(`DecompressionStream` is reachable). Runs in that window: `135 cases` and
`136 cases`, both `0 heap-corruption, 29 threw, 0 slow` - i.e. the whole light
census plus the ramp, and one of them with the 256 MiB canvas as well.

## Section N: parser payloads, 12 cases

The census settles what is worth building next. These are PARSERS, not size
arithmetic, so the only way in is bytes that lie about their own structure. Every
payload is hand-built, under 1 KiB, and malformed in exactly one way, so the parser
has to walk it before it can refuse it:

* N-01 WOFF2 header with `numTables = 0xFFFF`
* N-02 SFNT whose table count claims 0xFFFF entries
* N-03 `glyf`/`loca` pair with an offset past the end of the file
* N-04 `cmap` format 4 with `segCountX2 = 0xFFFF` and no segments
* N-05 SVG-in-OT (`SVG ` table) with a 1e9 viewBox and path coordinates
* N-06 PNG `IHDR` 0x7FFFFFFF square with no `IDAT`
* N-07 PNG chunk claiming a length of 0x7FFFFFFF
* N-08 GIF screen descriptor 0xFFFF x 0xFFFF
* N-09 WebP `VP8X` canvas 0xFFFFFF plus a bogus RIFF size
* N-10 AVIF `ftyp` box with size 0xFFFFFFFF
* N-11 deflate stream of 0xFF bytes
* N-12 gzip header followed by garbage

The font cases that load also exercise the GLYPH path - `document.fonts.add`, set
the family on a canvas ctx, `measureText`, `fillText`, read a pixel back - because
that is where SVG-in-OT class bugs actually live, not in the header parse.

## The dry run killed itself on the first cut of N-11/N-12, and that was useful

Node printed `Z_DATA_ERROR / incorrect header check` and EXITED before any summary:
a malformed deflate stream reports its failure on the stream, so a try/catch around
`write()` never sees it - the rejected promise was simply leaked. On the console that
would have been an unhandled rejection at best and a lost run at worst.

Two fixes: every promise in `tryDecompress` is now settled inside its own catch
(write, close and each read), and the page gained an
`unhandledrejection` listener that reports as its own tag, so a leaked rejection is
visible instead of silent. That listener is a genuine addition to the oracle set - it
catches a class of failure `window.onerror` cannot see.

Re-verified after the fix: 116 cases (114 light + 2 compression), TRY/OK 116/116,
0 corruption, **0 error lines**, `_done` posted, exit 0, with N-11/N-12 both
reporting `read-refused:TypeError` - refused cleanly through the read path. 58,420
bytes, 0 backticks / 0 non-ASCII / 0 CR, `node --check` clean.

Hardware light census is now 96 + 20 (J) + 10 (M) + 10 (N fonts/images) + 2 (N
compression) = 138 cases.


================================================================================
## N-10 WAS LISTED TWICE, AND THE CONSOLE HAS NOT LOADED SINCE 11:07:20
(2026-10-08, 11:12)

### A real defect in section N, found by auditing rather than by a run

The N payload array had ELEVEN entries but only ten names: the last line,
`['N-10 AVIF ftyp with a huge box size', ...]`, was present TWICE. Effect if it had
shipped: `TRY N-10` / `BOMB N-10` emitted twice, `STATUS['N-10']` written twice, and
the light census would have read 139 where the record says 138 - a silent off-by-one
in exactly the number every future run gets compared against. It also means the
"0 duplicate case ids" hygiene step was too weak: it only looked at ids, not at the
number of array entries, so a duplicated ENTRY that kept one id passed it.

Fix: the duplicate line is deleted, with a comment recording why. The hygiene step is
now `_hyg.py`, which counts the ids AND reports the per-section breakdown, so a
repeated entry is visible as a count that does not match the section's own numbering.

    file           ov_probe.html
    bytes          58412
    md5            4d1192ab89e155f5c5afad3d6ad791a7
    backticks      0
    CR bytes       0
    non-ascii      0
    case ids       177 distinct / 177 total
    duplicates     none
      A 16  B 16  C 20  D 20  E 12  F 12  G 9  H 1  J 20  K 17  L 12  M 10  N 12

Offline dry run after the fix (`_v8run4_light.txt`): 116 cases, TRY/OK 116/116,
nothing missing, N-11/N-12 both `read-refused:TypeError`, `_done` posted, exit 0.
Light census on hardware is unchanged and exact: 96 + 20 (J) + 10 (M) + 10 (N
fonts/images) + 2 (N compression) = **138 cases**.

Installed: master = installed = served, md5 4d1192ab89e155f5c5afad3d6ad791a7,
58,412 bytes, served 200 / 58,412 with `Host: manuals.playstation.net`. The 547-byte
answer that follows it in the same second is the cooldown stub working as designed
(127.0.0.1 had just taken its slot). `py_compile` clean, `__pycache__` removed.

### Where the console actually is

The last thing 192.168.137.102 asked us for was a DNS query at 11:06:59 and the
page itself at 11:07:20, and that run (SUMMARY 136 cases, light 126) was the PRE-N build - the log
contains zero `N-` case ids, so section N has still never run on hardware. Since
11:07:20: no HTTP request from the console, no DNS query from the console, no stub
serve for its IP. A load of the guide produces at least a DNS query even when the
page never arrives, so the console has simply not asked.

Server readiness re-proved without disturbing the console's own cooldown slot:
UDP 53 is bound on 192.168.137.1 by the listener PID, `manuals.playstation.net`
answers 192.168.137.1, `api.playstation.com` answers NXDOMAIN.


================================================================================
## SECTION N RAN ON HARDWARE: 138 CASES, EVERY PAYLOAD REFUSED (2026-10-08, 11:14)
================================================================================

Load at 11:14:24, whole run done by 11:14:29 - five seconds for 138 cases, and the
count is EXACTLY the documented light census (96 A-F + 20 J + 10 M + 10 N font/image +
2 N compression). `[WIN] SUMMARY: 138 cases, 0 heap-corruption, 29 threw, 0 slow`.
The oracle was armed and proved itself in the same run: `SELFTEST spray rebuilt,
verifies: YES`, `SELFTEST detector after a deliberate write: FIRED` (sentinel0 byte 17
is 123 want 119). Every N case is complete - TRY 1 / OK 1 / BOMB 1 for all twelve.

```
BOMB N-01 WOFF2 header, numTables 0xFFFF            status=ok ms=12 rejected:NetworkError
BOMB N-02 SFNT with bogus numTables                 status=ok ms=5  rejected:NetworkError
BOMB N-03 glyf offset beyond the file               status=ok ms=3  rejected:NetworkError
BOMB N-04 cmap format 4, segCountX2 0xFFFF          status=ok ms=4  rejected:NetworkError
BOMB N-05 SVG-in-OT with extreme viewBox            status=ok ms=4  rejected:NetworkError
BOMB N-06 PNG IHDR 0x7FFFFFFF square, no IDAT       status=ok ms=5  rejected:InvalidStateError
BOMB N-07 PNG chunk length 0x7FFFFFFF               status=ok ms=4  rejected:InvalidStateError
BOMB N-08 GIF screen descriptor 0xFFFF              status=ok ms=5  rejected:InvalidStateError
BOMB N-09 WebP VP8X canvas 0xFFFFFF                 status=ok ms=8  rejected:InvalidStateError
BOMB N-10 AVIF ftyp with a huge box size            status=ok ms=5  rejected:InvalidStateError
BOMB N-11 deflate stream of 0xFF bytes              status=ok ms=12 read-refused:TypeError
BOMB N-12 gzip header then garbage                  status=ok ms=0  read-refused:TypeError
```

Read: not one payload was ACCEPTED, not one refused slowly, and the sentinel spray never
changed - `0 heap-corruption` and no `UNHANDLED REJECTION` line. The image half is the
strongest of the three, because `InvalidStateError` from `createImageBitmap` is the
decoder's own verdict on bytes it has already been handed; ten different structural lies
(IHDR sizes, chunk lengths, screen descriptors, VP8X canvas, an 0xFFFFFFFF box) each
walked in and were turned back. The compression pair matches the reference engine
exactly - V8 gives `read-refused:TypeError` for both N-11 and N-12, the console gives
the same for both - so there is no divergence there either.

So section N closes as a clean NEGATIVE at this level: these parsers refuse malformed
input rather than trusting it. That is a real, reportable answer, not an absence of
evidence - and it is BOUNDED, which matters for the bounty write-up: it says every
structural lie we thought of is handled, not that these parsers are bulletproof.

### The hole I did not want to leave in it: the font half had not proved its own reach

All five font payloads travel as `data:font/ttf;base64,...`. `rejected:NetworkError` is
exactly what a FETCH-LAYER refusal looks like too, and `grep -i "LOADED"` over the whole
log shows that no font case has EVER loaded on this console - so nothing in the evidence
showed that a data: URL font is fetchable here at all. If it is not, then N-01..N-05
never reached a parser and prove nothing, while looking identical in the log to a
parser refusal. A negative whose instrument is unproven is not a finding.

Three changes, all in the installed build:

* **N-C1 / N-C2, two controls that must say LOADED**, placed FIRST in section N so the
  verdict is read before the payloads. They load the same REAL font (58,532 bytes of
  Tahoma Bold, served beside the page as `_cal.ttf`) down the two different roads - over
  the wire (`url(_cal.ttf)`) and through a data: URL built from the fetched bytes - so
  the two delivery paths are separated from the parse. If either control fails, the page
  emits `FONT INSTRUMENT INVALID this load: ... the font payload cases above prove
  NOTHING on this load` as a summary line, in as many words. The controls exercise the
  glyph path too (register, set the family, `measureText`, `fillText`, pixel readback).
* **N-01 now declares `font/woff2`** instead of `font/ttf`. WOFF2 bytes labelled ttf
  invite the engine to pick the wrong decoder, and then a refusal would say nothing
  about the WOFF2 decoder that the case exists to poke.
* **Every font case now gets its own family name** (`nf_n1`, `nf_c1`, ...). With one
  shared family, a case reporting LOADED could be rendering with a font an earlier case
  had registered, and the pixel readback would have been measuring the wrong font.

Verified: 60,857 bytes, md5 `bfd3d4d9b80d61b9f8cf6202d71c2214`, 0 backticks / 0 CR /
0 non-ASCII, `node --check` clean, 23 distinct ids with no duplicates and N reading
`C1 C2 01..12`; dry run 116 cases, TRY/OK 116/116, `_done`, exit 0; master = installed =
served (`200 / 60,857`) and the fixture serves as `200 / 58,532 font/ttf`
(md5 `b8580701c445df583a6d32c1e8169e13`).

**The light census with the controls is now 140 cases** (96 + 20 + 10 + 12 payload + 2
compression). A run that reports anything other than 140 is telling us something.

### One operational note

The console loaded once at 11:14:24 and again at 11:14:32; the second load was served the
45-second resting page, which is the cooldown doing its job and cost nothing but a click.
One click, then wait - the page takes about five seconds.


================================================================================
## THE CALIBRATION ANSWERED LOADED: SECTION N IS NOW INSTRUMENT-VALIDATED
(2026-10-08, 11:21 and 11:22, two console runs)
================================================================================

Two loads landed back to back, both on the control build, both complete:

```
11:21:39 load -> light 140 cases, 0 heap-corruption, 29 threw, 0 slow   [?heavy=1]
                 FINAL SUMMARY 149 cases              (140 + the 9 heavy cases)
11:22:25 load -> light 140 cases, 0 heap-corruption, 29 threw, 0 slow   [?heavy=1&canvas=1]
                 FINAL SUMMARY 150 cases              (140 + 9 heavy + the 256 MiB canvas)
```

The light census is EXACTLY the predicted 140 - the duplicated N-10 would have made it
141 and that is precisely the kind of off-by-one the removal was for. No heap corruption
in either run, and the console survived the whole heavy tail twice, including the 256 MiB
canvas, which is the behaviour the opt-in gating was built to allow.

### The question the controls existed to answer, answered

```
[info] calibration font: fetched 58532 bytes from _cal.ttf
BOMB N-C1 CONTROL real font over the wire - MUST say LOADED   status=ok ms=620 LOADED w=43.0 px=0
BOMB N-C2 CONTROL same real font through a data: URL - MUST say LOADED status=ok ms=4   LOADED w=43.0 px=0
[info] FONT INSTRUMENT VALID this load: both controls loaded the real font, one over the
       wire and one through a data: URL. So a font case above reporting rejected:NetworkError
       was refused BY THE PARSER - the bytes reached it. The font half of section N counts.
```

So the hole is closed with evidence rather than argument: this engine DOES fetch and parse
a font through a `data:font/ttf;base64,` URL, which is the exact vehicle N-01..N-05 use.
`rejected:NetworkError` from those five is therefore the parser's verdict on bytes it
received, not the fetch layer refusing a URL scheme - and the negative stands on all five
font cases as well as the image and compression halves.

All twelve payload verdicts came back IDENTICAL in both runs (N-01..N-05
`rejected:NetworkError`, N-06..N-10 `rejected:InvalidStateError`, N-11/N-12
`read-refused:TypeError`), so the section-N negative is now repeatable rather than a
single observation: two independent loads, twenty-four payload executions, no case
accepted, no sentinel change.

### And the controls immediately caught a defect in my own readback

`px=0` in both controls. The glyph path read `getImageData(0,0,8,8).data[0]` - the
top-left CORNER - while the glyph is drawn at x=2 with its baseline at y=40. The corner is
empty by construction, so that byte is 0 whether the glyph drew or not: the readback could
not tell a rendered glyph from a blank canvas, and every "the glyph path was exercised"
claim in this record rested on it. Only a control could have exposed that, because it is
the first case that ever loaded a font.

Fix: count the INK over the whole 64x64 canvas (`for(i=3;i<d.length;i+=4) if(d[i]) ink++`)
and report `LOADED w=<advance> ink=<pixels>`, where `ink>0` is a real statement that the
glyph drew. `w=43.0` for `Ag` at 32px already showed the font's own metrics were in
effect.

Honest limitation on the new check: the readback lives inside `tryFontSrc`, which only
runs when a DOM and a canvas exist, so the offline dry run cannot exercise it (there
`ctxOf` throws and the case reports THREW, as designed). The next console load is what
proves the replacement - the two controls must report `ink` well above zero.

Build now installed: 61,450 bytes, md5 `00cd2705f032e6c20fc8ca365b83ed42`, 0 backticks /
0 CR / 0 non-ASCII, 23 distinct ids with no duplicates, `node --check` clean, dry run
116 cases TRY/OK 116/116 with `_done` and exit 0, master = installed = served
(`200 / 61,450`). Light census stays 140; the heavy tail makes 149 and 150.


================================================================================
## THE NEW READBACK IS PROVEN: ink=605, AND SECTION N IS CLOSED BOTH WAYS
(2026-10-08, 11:25, 11:27, 11:28)
================================================================================

Three more console runs on the ink build, all complete:

```
11:25:47 load -> light 140 cases, 0 heap-corruption, 29 threw, 0 slow   heavy SKIPPED
11:27:34 load -> light 140 cases, 0 heap-corruption, 29 threw, 0 slow   ?heavy=1
                 FINAL SUMMARY 149 cases
11:28:2x load -> light 140 cases, 0 heap-corruption, 29 threw, 0 slow   ?heavy=1&canvas=1
                 FINAL SUMMARY 150 cases
```

```
BOMB N-C1 CONTROL real font over the wire - MUST say LOADED      LOADED w=43.0 ink=605  ms=555
BOMB N-C2 CONTROL same real font through a data: URL - MUST say LOADED LOADED w=43.0 ink=605 ms=4
BOMB N-C1 (second run)                                          LOADED w=43.0 ink=605  ms=793
BOMB N-C2 (second run)                                          LOADED w=43.0 ink=605  ms=5
```

`ink=605` is 605 pixels of real glyph ink, and it is IDENTICAL in both controls and in
both runs - which is what a correct whole-canvas count should look like for the same two
glyphs at the same size, and is exactly what the old corner sample could not produce (it
said 0 always). The `px=0` lines in the log all predate this build and are the evidence of
the defect, kept deliberately: the run that proves the fix sits next to the run that
exposed the bug. The glyph-render claim in this record is now measured rather than
asserted.

Section N is therefore closed in both directions at this level: every malformed payload is
refused, AND the instrument that says so is demonstrated to reach the parsers (fonts over
two delivery paths, images through a real decoder, compression through the stream reader).
No further console work is needed for section N.

Small operational fact worth keeping: the 45-second slot is set by the last PROBE serve
only - a stub serve does NOT extend it. That is why the countdown pages at 11:23:14,
11:26:00 and 11:27:51 cost nothing: the next load after the window opened was served the
probe, at 11:25:47, 11:27:34 and 11:28:2x respectively.
================================================================================
## THE REGEX CENSUS BECOMES SOMETHING ANYONE CAN RUN (2026-10-08, 11:45)
================================================================================

New artifacts, all in this folder and mirrored to the served tree:

```
regex_census.html   27,275 bytes  md5 61b15fb06de7a90b1a1a51df723ab4a1
regex_census.js     21,638 bytes  md5 95dc410cdfe0769fbb115b63c300cb40
REGEX_CENSUS.md     the README: what it is, how to run it, what it is not
_mk_census.py       the generator; refuses to emit unless the table reproduces the census
```

One HTML file and one Node script, no dependencies and no network access. Both run the same 98
cases - every case from the five regression test files Apple added in 956f6fb, with Apple's own
expected values - on whatever engine opens it, and print where that engine disagrees.

## The number this record has been repeating was wrong, and building the tool is what showed it

The record has said "25 of Apple's 102 upstream regression cases still fail". The measured
census is **21 of 98**:

* the 98 are what actually run: A1 19, A2 13, A3 11, A4 10, A5 45. The four that made "102" are
  the replace/matchAll cases that live in another section, so they were never part of the
  ported set;
* of the 25, four are B1 - our own C3 oracle cases, not Apple's - so "25 of Apple's" was never a
  defensible sentence. The honest form is 21 of Apple's 98, plus 4 of our own cases that also
  diverge.

Re-derived from the raw log rather than from the prose: every CASE line of the 09:33 run was
parsed, compared against the ported expectation, and the per-file result is 9 / 6 / 3 / 2 / 1 =
21. The generator now refuses to build the artifacts unless the table reproduces exactly that,
so the number cannot drift again without the build failing.

## Two escaping traps that would each have shipped a wrong number

1. **The logged value is escape-encoded.** esc() in the probe turns every character outside
   32..126 into the literal text backslash-u-XXXX, and the probe's own verdict used the value
   BEFORE that encoding. Comparing the logged text against an expectation containing the real
   character invents divergences: A4-06 and A5-08 came out as failures (23 instead of 21) from
   that alone, and neither carries a verdict=PRE-FIX in the log, which is the log itself saying
   it did not diverge.
2. **An astral character arrives as TWO escapes.** Decoding each escape on its own yields two
   lone surrogates, which a string holding the real character can never equal, so the pair has
   to be recombined. A genuinely unpaired escape is left as a lone surrogate on purpose: on
   those cases the engine really did hand back half a pair, and that is a finding, not an
   extraction bug.

## Verification of the artifacts, and the bug they caught in themselves

* `node regex_census.js`: **V8 (Node 24) diverges on 0 of 98**, which is what validates the
  transcription - had an expectation been copied wrong, V8 would fail it. The recorded console
  values diverge on 21 of 98, and the tool says exactly that in its summary.
* The page's self-test runs before the table and reports a deliberately wrong expectation as
  DIVERGES. A harness that cannot report a failure fails its own test and says so in red.
* `node --check` on the script extracted from the HTML caught a REAL bug in the first build: a
  bare backslash-u-XXXX inside a JS string literal is an invalid escape sequence, so the whole
  script would have failed to parse and the page would have been blank on the console. The
  generator now inserts that backslash through a placeholder instead of by hand.
* Hygiene: 0 backticks, 0 CR, 0 non-ASCII in both files; the embedded table parses as JSON with
  98 rows and 21 console divergences.
* Rendered and inspected in a browser: 98 rows, 21 PS5 divergence badges, self-test card green,
  header and both legend lines present. One apparent data error - A1-07 reading [4,"b"] for a
  two-character input - was investigated in the DOM and is NOT an error: the engine, the
  expectation and the console all say [1,"b"], and the neighbouring row's escape text had been
  misread.
* Served: 200 / 27,275 and 200 / 21,638, md5 matching the local copies.

## Limitation, stated

The census page has not been loaded on the console yet, so the PS5 column in it is the RECORDED
value from 09:33 rather than a live read. The next console session should load regex_census.html
through the guide: if it renders there and its own "this engine" columns report 21 of 98, the
tool is proven end to end on the platform it was written about - and anyone else with a console
gets the same answer in one click.

================================================================================
## PUBLIC PACKAGE BUILT (2026-10-08, 12:05)
================================================================================

`ps5-fw14-webkit-notes.zip` (133,896 bytes, 15 files) next to this project, built by
`_pack_build.py` so it can be rebuilt in one command. Contents: README, FINDINGS (what worked,
what half worked, what only looked like a finding, what failed, what was never tried), tools
(the census page and runner, the probe, the generator, the extracted case table and console
values), server (harness + how to run it), notes (this record), evidence (every result line of
the 09:33 console run, plus the console's own report line), posts (the X drafts), and a
MANIFEST with the md5 of every file.

The build runs a trace scan over every packaged file for strings that would reveal how the work
was produced, and it refuses to be quiet about hits. One hit was found and it was a false
positive: a cited writeup whose domain ends in a two-letter country code that also spells a
common abbreviation. That citation now carries the article title without its domain. No other
file matched, and the scan is part of the build rather than a one-off.

Verified after building: the zip's 15 members extract cleanly, the packaged tools are
byte-identical to the originals (md5), `node tools/regex_census.js` runs from inside the
extracted package and reports its self-test OK with V8 divergent on 0 of 98, and every one of the
14 manifest entries matches its file.

Still outstanding: the census page has never been loaded ON the console, so the PS5 column in it
is the recorded 09:33 data. That is the one click that would close the loop.

================================================================================
## THE READ THE PACKAGE SHOULD PRODUCE, WRITTEN INTO IT (2026-10-08, 12:20)
================================================================================

FINDINGS.md now opens with a "how to read this" block that states the framing plainly, so nobody
has to reconstruct it from the detail: the regex numbers are Apple's own expectations and the
only confirmed defect class; F3 is a spec-level violation Apple's fix did not close and NOT a
chain candidate, with the reason (the one unchecked read needs a capture whose start exceeds its
end, and ~1,300 cases never produced one); the useful half of that family is the false positives,
not the missed matches; and the memory negative comes from a write-only instrument that cannot
see a read or a write outside the sprayed region.
