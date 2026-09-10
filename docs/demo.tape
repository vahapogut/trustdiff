# Demo recording for the README, rendered with vhs (https://github.com/charmbracelet/vhs)
# by .github/workflows/demo.yml.
#
# The trustdiff binary must be on PATH. Local run: vhs docs/demo.tape
#
# Two things about this file are the result of five failed runs, and both are worth
# leaving written down.
#
# The size is set in pixels with Width and Height rather than in Set Columns and
# Set Rows. Columns and Rows arrived in vhs v0.12.0, published 2026-09-09, which is
# the same day this recording first failed, and they were the only unusual thing the
# tape asked for. Width and Height are the settings vhs has always had. If Columns
# and Rows are ever wanted back, change one thing at a time and check that a file
# actually appears, because vhs reports success either way.
#
# It records one command, the three-package card, which is what docs/PLAN.md task
# 1.15 asks the GIF to show. An earlier version also recorded
# check npm:flatmap-stream@0.1.1. That card is around thirty lines now, because the
# package is gone from the registry and every history check reports itself as
# skipped, so it needs a frame tall enough to make an awkward README image and long
# enough to make a heavy one. The README carries it as a text block instead.

Output docs/demo.gif

Require trustdiff

Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 700
Set Padding 20
Set TypingSpeed 40ms

# Warm the cache off camera. The recorded run then answers from disk, so the demo
# shows the tool rather than the network, and a rate-limited registry (the npm
# downloads API answers 429 to shared CI addresses often enough to matter) delays
# this hidden run instead of timing the recording out.
Hide
Type "trustdiff check npm:express@4.19.2 pypi:requests cargo:serde >/dev/null 2>&1; echo CACHE-WARMED"
Enter
# Wait on a sentinel the command prints rather than on the prompt, whose shape
# depends on the shell vhs starts.
Wait+Screen@300s /CACHE-WARMED/
Type "clear"
Enter
Sleep 500ms
Show

# The acceptance scenario of docs/PLAN.md task 1.15: three packages, three verdicts.
Type "trustdiff check npm:express@4.19.2 pypi:requests cargo:serde"
Sleep 500ms
Enter
# The summary line is the last thing the report prints.
Wait+Screen@300s /Exit code/
Sleep 6s
