#!/usr/bin/env python3
"""Generate the standalone regex census artifacts.

Inputs (all produced from the original probe, never hand-edited):
  _u_cases.json   the A-section case table, extracted by running the probe's own
                  kL()/jL() calls through Node, so patterns, flags and inputs are the
                  probe's own values rather than a retyping of them
  _u_hw_all.json  the console's value per case id, parsed out of ascend_raw.log from
                  the 09:33 run on PS5 fw 14.00

Outputs:
  regex_census.js    a Node runner, no dependencies
  regex_census.html  the same logic and the same table, self-contained, no requests,
                     works from file:// and on the console's own browser

Both files stay pure ASCII: non-ASCII in the data is escaped as \\uXXXX, and '<' is
escaped too so nothing in the table can close the script element early.
"""
import json
import re

CASES = json.load(open('_u_cases.json', encoding='utf-8'))
HW = json.load(open('_u_hw_all.json', encoding='utf-8'))

# The probe escapes every non-ASCII character in what it posts, so a match that
# contains an astral character arrives in the log as the literal text "\\ud83d\\ude00".
# The probe's OWN comparison used the unescaped value, so comparing the escaped text
# against an expectation that contains the real character invents two divergences
# (A4-06 and A5-08) that the engine never had. Decode before comparing; the count then
# matches the probe's own per-file census exactly.
ESC = re.compile(r'\\u([0-9a-fA-F]{4})')
# An astral character arrives as TWO escapes, a high surrogate then a low one. Decoding
# them one at a time leaves two lone surrogates, which a string containing the real
# character can never equal - and that is exactly the false divergence this had to lose.
# A single unpaired escape is left as a lone surrogate on purpose: on those cases the
# engine really did hand back half of a pair, and that is a finding, not a decoding bug.
PAIR = re.compile(r'\\u(d[89ab][0-9a-fA-F]{2})\\u(d[c-f][0-9a-fA-F]{2})', re.I)

def _pair(m):
    hi = int(m.group(1), 16) - 0xD800
    lo = int(m.group(2), 16) - 0xDC00
    return chr(0x10000 + (hi << 10) + lo)

def unescape_v(v):
    if not isinstance(v, str):
        return v
    v = PAIR.sub(_pair, v)
    return ESC.sub(lambda m: chr(int(m.group(1), 16)), v)

HW = {k: unescape_v(v) for k, v in HW.items()}

SOURCE = {
    'A1': 'regexp-interpreter-lookbehind-character-class-non-bmp.js',
    'A2': 'regexp-interpreter-lookbehind-fixed-count-non-bmp-character.js',
    'A3': 'regexp-interpreter-lookbehind-surrogate-half.js',
    'A4': 'regexp-interpreter-lookbehind-greedy-class-backtrack-non-bmp.js',
    'A5': 'regexp-lookbehind.js',
}

rows = []
for c in CASES:
    if not re.match(r'^A\d-', c['label']):
        continue                      # B/L sections are our own cases, not Apple's
    cid = c['label'].split(' ')[0]
    rows.append({
        'id': cid,
        'file': cid.split('-')[0],
        'desc': c['label'][len(cid) + 1:],
        'src': c['src'],
        'flags': c['flags'],
        'subj': c['subj'],
        'li': c['li'],
        'want': c['want'],
        'hw': HW.get(cid),
    })

assert len(rows) == 98, 'expected the 98 ported cases, got %d' % len(rows)
assert all(r['want'] and r['hw'] for r in rows), 'a case is missing its expectation or its console value'

# Hard gate: the table is only allowed to ship if it reproduces the console census that
# was measured independently (9 / 6 / 3 / 2 / 1).
for f, expect in (('A1', 9), ('A2', 6), ('A3', 3), ('A4', 2), ('A5', 1)):
    n = sum(1 for r in rows if r['file'] == f and r['hw'] != r['want'])
    assert n == expect, '%s: %d console divergences in the table, expected %d' % (f, n, expect)

table = json.dumps(rows, ensure_ascii=True, separators=(',', ':'))
table = table.replace('<', '\\u003c')
srcjs = json.dumps(SOURCE, ensure_ascii=True, separators=(',', ':'))

CORE = """
var CASES = __TABLE__;
var SOURCE = __SOURCE__;

// The probe's own value formatter, reproduced exactly: [index, group0, group1, ...]
// as JSON, with a replacer that turns a NON-PARTICIPATING group into the string
// "<undefined>" instead of letting JSON.stringify turn it into null. That detail
// matters: A5-03's expectation is written with <undefined> in it, so a tool that
// normalised it to null would report a divergence where there is none.
var REPL = function(k, v){ return (v === undefined) ? '<undefined>' : v; };

function fmtIndexed(m){
    if(!m) return 'null';
    return JSON.stringify([m.index].concat([].slice.call(m)), REPL);
}

function runCase(c){
    var re;
    try{ re = new RegExp(c.src, c.flags); }
    catch(e){ return 'THREW:' + ((e && e.name) || '?'); }
    try{
        if(c.li !== null && c.li !== undefined) re.lastIndex = c.li;
        return fmtIndexed(re.exec(c.subj));
    }catch(e){ return 'THREW:' + ((e && e.name) || '?'); }
}

// Two synthetic cases with known answers. The first expectation is deliberately WRONG,
// so a harness that cannot report a failure fails its own test here and says so loudly.
// Nothing else in the output is worth reading until this passes.
function selfTest(){
    var probes = [
        { src:'a', flags:'', subj:'a', li:null, want:'[0,"a"]' },
        { src:'a', flags:'', subj:'a', li:null, want:'null' }
    ];
    var want = ['PASS', 'DIVERGES'], got = [], ok = true, i;
    for(i = 0; i < probes.length; i++){
        var g = runCase(probes[i]);
        var v = (g === probes[i].want) ? 'PASS' : 'DIVERGES';
        if(v !== want[i]) ok = false;
        got.push(g + ' -> ' + v);
    }
    return { ok: ok, detail: got };
}

function census(){
    var out = [], per = {}, i, c, g;
    for(i = 0; i < CASES.length; i++){
        c = CASES[i];
        g = runCase(c);
        per[c.file] = per[c.file] || { n: 0, div: 0 };
        per[c.file].n++;
        if(g !== c.want) per[c.file].div++;
        out.push({ c: c, got: g, ok: (g === c.want) });
    }
    return { rows: out, per: per };
}

function hwSummary(){
    var n = 0, per = {}, i;
    for(i = 0; i < CASES.length; i++){
        if(CASES[i].hw !== CASES[i].want){
            n++;
            per[CASES[i].file] = (per[CASES[i].file] || 0) + 1;
        }
    }
    return { n: n, per: per };
}
"""

NODE_TAIL = """
var st = selfTest();
console.log('SELF-TEST: ' + (st.ok ? 'OK - the harness reports a wrong expectation as DIVERGES'
                                  : 'FAILED - results below cannot be trusted'));
if(!st.ok) console.log('  ' + st.detail.join('\\n  '));

var res = census();
var files = Object.keys(res.per).sort();
var i, r;

console.log('');
console.log('engine under test: ' + (typeof process !== 'undefined'
              ? 'Node ' + process.version + ' (V8)'
              : 'this browser'));
console.log('');
for(i = 0; i < files.length; i++){
    var f = files[i];
    console.log('  ' + f + '  ' + pad(res.per[f].div, 2) + ' of ' + pad(res.per[f].n, 2)
                + ' diverge   ' + SOURCE[f]);
}
var total = 0;
for(i = 0; i < res.rows.length; i++) if(!res.rows[i].ok) total++;
console.log('');
console.log('THIS ENGINE: ' + total + ' of ' + res.rows.length + ' cases diverge from Apple\\'s expectations');
console.log('PS5 14.00 (recorded 2026-10-08 09:33): ' + hwSummary().n + ' of ' + res.rows.length + ' diverge');
console.log('');
if(total){
    console.log('divergences on this engine:');
    for(i = 0; i < res.rows.length; i++){
        r = res.rows[i];
        if(!r.ok) console.log('  ' + r.c.id + '  ' + r.got + '  want ' + r.c.want + '   ' + r.c.desc);
    }
} else {
    console.log('no divergences here. on a PS5 on fw 14.00 the same table shows the 21 above.');
}

function pad(s, n){ s = String(s); while(s.length < n) s = ' ' + s; return s; }
"""

HTML_TAIL = """
var st = selfTest();
var res = census();
var hw = hwSummary();
var files = Object.keys(res.per).sort();
var lines = [], i, r, row;

lines.push('<h1>regex census</h1>');
lines.push('<p class="sub">' + CASES.length + ' cases ported from the five regression test files Apple added in commit ' +
           '956f6fb (320492@main). Every expectation in the last-but-one column is Apple&rsquo;s own, taken from those ' +
           'files; the last column is what a PS5 on firmware 14.00 answered on 2026-10-08.</p>');

lines.push('<div class="card ' + (st.ok ? 'good' : 'bad') + '">');
lines.push('<strong>SELF-TEST: ' + (st.ok ? 'OK' : 'FAILED') + '</strong> &mdash; ' +
           (st.ok
             ? 'the harness reports a deliberately wrong expectation as DIVERGES, so a failure below is a real one: ' + st.detail.join(' / ')
             : 'the harness cannot detect a wrong answer, so nothing else on this page means anything'));
lines.push('</div>');

lines.push('<div class="card">');
lines.push('<div class="big">THIS ENGINE: <strong>' + total() + ' of ' + CASES.length + '</strong> diverge from Apple&rsquo;s expectations</div>');
lines.push('<div class="big">PS5 14.00 (recorded): <strong>' + hw.n + ' of ' + CASES.length + '</strong> diverge</div>');
lines.push('<div class="per">');
for(i = 0; i < files.length; i++){
    var f = files[i];
    lines.push('<span class="pill">' + f + ': ' + res.per[f].div + '/' + res.per[f].n + '</span>');
}
lines.push('</div>');
lines.push('</div>');

lines.push('<p class="legend">expectation = Apple&rsquo;s own value, from the test file named.' +
           ' this engine = what the browser you are reading this on just produced.' +
           ' PS5 14.00 = the value recorded from a PlayStation 5 on 2026-10-08.' +
           ' Characters above U+007F are shown as __BSL2__uXXXX escapes so a row stays on one line and can be copied by eye.</p>');
lines.push('<p class="legend">' + files.map(function(f){ return '<span class="mono">' + f + '</span> = ' + esc(SOURCE[f]); }).join('&nbsp;&nbsp;') + '</p>');
lines.push('<table><thead><tr><th>case</th><th>pattern</th><th>input</th><th>Apple&rsquo;s expectation</th>' +
           '<th>this engine</th><th>PS5 14.00</th><th>verdict</th></tr></thead><tbody>');
for(i = 0; i < res.rows.length; i++){
    r = res.rows[i];
    var hwDiv = (r.c.hw !== r.c.want);
    lines.push('<tr class="' + (r.ok ? 'pass' : 'div') + '">' +
        '<td class="id" title="' + esc(r.c.desc) + '">' + r.c.id + '</td>' +
        '<td class="mono">/' + esc(r.c.src) + '/' + esc(r.c.flags) + '</td>' +
        '<td class="mono">' + esc(disp(r.c.subj)) + (r.c.li !== null ? ' <span class="li">li=' + r.c.li + '</span>' : '') + '</td>' +
        '<td class="mono want">' + esc(r.c.want) + '</td>' +
        '<td class="mono">' + esc(r.got) + '</td>' +
        '<td class="mono hw' + (hwDiv ? ' hwdiv' : '') + '">' + esc(r.c.hw) + '</td>' +
        '<td class="verdict">' + (r.ok ? 'ok' : 'DIVERGES') +
            (hwDiv ? ' <span class="ps5bad" title="the recorded PS5 value disagrees with Apple">PS5</span>' : '') + '</td>' +
        '</tr>');
}
lines.push('</tbody></table>');

lines.push('<h2>what this is, and what it is not</h2>');
lines.push('<p>A divergence here is a <strong>wrong answer</strong>: a lookbehind that finds no match where one exists, ' +
           'or a negated lookbehind that matches where it must not. On firmware 14.00 the 21 failures decompose into three ' +
           'root causes, all in the non-BMP handling of lookbehind: a sticky <span class="mono">lastIndex</span> inside a ' +
           'surrogate pair not mapped through the code point list, the backward class path walking a pair as two code units, ' +
           'and the forward <span class="mono">/u</span> scan entering pair interiors. The third is a forward-path violation ' +
           'that is not among the four bugs commit 956f6fb fixed.</p>');
lines.push('<p>It is <strong>not</strong> a memory-safety result. No out-of-bounds read, no out-of-bounds write, no ' +
           'corruption of any kind was observed while these cases ran; a 49 KB spray of sentinel ArrayBuffers re-verified ' +
           'after every single case never changed once across those runs. Correctness bugs of this shape are worth reporting ' +
           'and are not an exploit.</p>');
lines.push('<p>To check another engine, run <span class="mono">node regex_census.js</span>, or just load this page. ' +
           'The expectations and the console values are the same data in both.</p>');

document.getElementById('out').innerHTML = lines.join('');

function total(){ var n = 0, i; for(i = 0; i < res.rows.length; i++) if(!res.rows[i].ok) n++; return n; }
function esc(s){ return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
function disp(s){
    var out = '', i, code;
    for(i = 0; i < String(s).length; i++){
        code = String(s).charCodeAt(i);
        if(code > 126) out += '\\\\u' + ('000' + code.toString(16)).slice(-4);
        else out += String(s).charAt(i);
    }
    return out;
}
"""

HTML_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>regex census - lookbehind and non-BMP, PS5 firmware 14.00</title>
<style>
body { background:#101216; color:#e8e8ea; font:16px/1.5 -apple-system,'Segoe UI',Roboto,sans-serif; margin:0; padding:24px 28px 60px; }
h1 { font-size:30px; margin:0 0 6px; letter-spacing:-0.5px; }
h2 { font-size:19px; margin:32px 0 8px; }
p { max-width:1100px; }
p.sub { color:#9aa0a8; max-width:1100px; }
.card { background:#181c22; border:1px solid #262c34; border-radius:10px; padding:14px 18px; margin:14px 0; max-width:1400px; }
.card.good { border-color:#2c5a37; }
.card.bad { border-color:#7a2a2a; background:#221618; }
.big { font-size:20px; margin:2px 0; }
.per { margin-top:10px; }
.pill { display:inline-block; background:#20262e; border:1px solid #2b333d; border-radius:999px; padding:3px 12px; margin:3px 6px 3px 0; font-size:14px; color:#c8ced6; }
table { border-collapse:collapse; margin-top:10px; width:100%; max-width:1500px; }
th, td { text-align:left; padding:7px 10px; border-bottom:1px solid #232a32; vertical-align:top; }
th { font-size:13px; text-transform:uppercase; letter-spacing:0.06em; color:#8b929b; font-weight:600; }
td.mono { font-family:Consolas,'Liberation Mono',Menlo,monospace; font-size:14px; }
td.id { font-family:Consolas,monospace; font-size:14px; color:#9fd0ff; white-space:nowrap; }
tr.div td { background:#241a1c; }
tr.div td.verdict { color:#ff8181; font-weight:700; }
p.legend { color:#8b929b; font-size:14px; margin:6px 0 0; }
td.hwdiv { color:#ff9a9a; }
span.ps5bad { background:#4a1f24; color:#ff9a9a; border:1px solid #6b2b31; border-radius:4px;
              padding:1px 6px; margin-left:6px; font-size:11px; letter-spacing:0.04em; }
td.verdict { color:#6cd07f; font-weight:700; font-size:13px; }
td.hw { color:#c9b98a; }
span.li { color:#c9b98a; font-size:12px; }
</style>
</head>
<body>
<div id="out"></div>
<script>
"""

# The Node runner and the page must not disagree, so both are cut from the same core.
node_js = CORE.replace('__TABLE__', table).replace('__SOURCE__', srcjs) + NODE_TAIL + """
// runCase/census/selfTest are defined above; nothing in the Node path touches the DOM.
var _ = selfTest; var __ = census; var ___ = hwSummary; var ____ = pad;
process.exit(0);
"""
node_js = node_js.replace("""
// runCase/census/selfTest are defined above; nothing in the Node path touches the DOM.
var _ = selfTest; var __ = census; var ___ = hwSummary; var ____ = pad;
process.exit(0);
""", "")

# pad() is used before its declaration: hoisted, fine in both engines.
# A backslash inside the page's own string literals has to be written twice in the JS
# source, and hand-counting those is how the previous build shipped an invalid escape
# sequence that node --check caught. The placeholder keeps it impossible to miscount.
html_tail = HTML_TAIL.replace('__BSL2__', chr(92) * 2)
html = HTML_HEAD + CORE.replace('__TABLE__', table).replace('__SOURCE__', srcjs) + html_tail + "\n</script>\n</body>\n</html>\n"

open('regex_census.js', 'w', encoding='utf-8', newline='\n').write(node_js)
open('regex_census.html', 'w', encoding='utf-8', newline='\n').write(html)
print('rows:', len(rows), '| per file:', {k: sum(1 for r in rows if r['file'] == k) for k in sorted(SOURCE)})
print('console divergences in the table:', sum(1 for r in rows if r['hw'] != r['want']))
print('regex_census.js   %d bytes' % len(node_js))
print('regex_census.html %d bytes' % len(html))
