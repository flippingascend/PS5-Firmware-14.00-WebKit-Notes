# the harness

A console's browser has no address bar and no developer tools. The way in is the **User's Guide
link**: the console asks for a page on a PlayStation hostname, and if that name resolves to a
machine you control, you control the page. `ps5_server.py` is that machine.

## What it does

* **Answers DNS** on UDP 53 for the guide hostnames (`www`, `support`, `manuals`, `document`,
  `help` on the playstation names) with its own address, and answers NXDOMAIN for the API, store,
  CDN, update and telemetry hosts so the console cannot quietly reach the real ones.
* **Serves HTTPS and HTTP** on 443, 80 and 8765. Any file in the server's directory can be
  fetched by basename - no path traversal, the basename is what resolves.
* **Logs results.** A page POSTs to `/result` or `/report`, and every line is appended to
  `ascend_raw.log` with a timestamp and the client address. That file is the evidence: it is what
  `_u_hw_all.json` was parsed from.
* **Serves the probe once per client per 45 seconds.** See below.

## Running it

    python ps5_server.py

Expect a banner naming the page it will serve and the address to point the console at. On the
console: Settings, Network, Set Up Internet Connection, your connection, Advanced Settings, DNS
Settings, Manual, primary DNS = the address the banner prints. Then open the User's Guide from
Settings and follow the bottom link.

Configuration lives at the top of the file: `PAGE` is the page served for the guide link,
`PROBE_COOLDOWN` is the one-run window, and `PORT`s and the DNS bind address are next to them.

## Why the cooldown exists

An earlier version let a page ask for a re-run by carrying a flag in its own URL. That was a
mistake with a clear lesson: the console reloaded the URL after a memory kill and re-ran the
group that had just killed it, five times in 41 seconds. A limit that a page can bypass is not a
limit, so the current one lives in the server: one probe per client address per 45 seconds, and
anything inside the window gets a small inert page that counts down. It cannot be defeated from
the page, and the countdown page does not extend the window - the next load after it opens gets
the real probe.

The probe itself also carries a marker in `localStorage` so that the heavy allocation group runs
once per browser and needs an explicit `?heavy=1&canvas=1&again=1` link to repeat.

## Writing cases

The probe's shape is worth copying rather than reinventing:

* **Announce before, confirm after.** Each case emits `TRY <id>` before it runs and `OK <id>`
  after. A `TRY` with no `OK` is the case that killed the engine, and the id names it.
* **Result line per case:** `BOMB <id> <description> status=<verdict> ms=<time> <detail>`.
* **Verify the oracle every time.** The sentinel buffers are re-checked after every case, and one
  deliberate write at start-up proves the detector fires. A run with no corruption and no
  self-test is a run where the instrument was not armed.
* **Count the cases.** The total is the integrity check: a run that reports a different number
  lost a case somewhere.

## Known limits

* The server is single threaded: under a burst of POSTs it drops some, which shows up in the log
  as gaps. The probe's case count is what detects that.
* Windows may let this bind 80, 443, 8765 and UDP 53 without elevation; if not, run it as a
  service or move the ports and point the console at them.
* Restarting it: kill the process that `netstat` shows beside LISTENING, not the wrapper that
  launched it - they are different processes, and killing the wrapper leaves the listener up.
