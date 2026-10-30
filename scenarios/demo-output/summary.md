# Data pipeline demo: summary

Detector used: **python-validators** (Python validators; the C++ detect library was not used in this run). Names are found by a dictionary of the synthetic generator's names (a stand-in; GLiNER is Sprint 2). Images and canvases are blacked out whole (no OCR yet).

| page | values planted | detected | placeholders issued | leak check (values + encodings) | pixel check (planted values under solid black) | vault binding test | decoys kept (must stay visible) |
|---|---|---|---|---|---|---|---|
| login | 8 | 8 + 0 image/canvas (fail-closed) | 8 | 0 leaks | all covered | 9 sealed; right binding opens, 5 wrong bindings refused | 0/0 |
| checkout | 15 | 13 + 2 image/canvas (fail-closed) | 13 | 0 leaks | all covered | 13 sealed; right binding opens, 5 wrong bindings refused | 1/1 |
| support | 12 | 9 + 3 image/canvas (fail-closed) | 10 | 0 leaks | all covered | 15 sealed; right binding opens, 5 wrong bindings refused | 0/0 |
| video | 10 | 7 + 3 image/canvas (fail-closed) | 7 | 0 leaks | all covered | 7 sealed; right binding opens, 5 wrong bindings refused | 0/0 |
| devsettings | 10 | 10 + 0 image/canvas (fail-closed) | 9 | 0 leaks | all covered | 10 sealed; right binding opens, 5 wrong bindings refused | 0/0 |

Totals: 55 planted, 47 detected by the detector, 8 inside images/canvas (blacked out), 0 leaked, 47 placeholders issued.

Planted values the detector did NOT catch (by type): none.

Leak check: every planted value, as rendered and canonical, in these encodings: as is, case-folded, normalised (look-alikes/invisible characters removed), separators removed (digits only), base64, base64url, hex, URL-encoded, reversed digits, searched in all string content of what the AI would receive. Control: the same scan finds the values in the original DOM capture login 8/8, checkout 12/13, support 9/9, video 7/7, devsettings 10/10.

Session id of the demo vault: `61e66117b17ab467`. Placeholder numbers are random per run.
