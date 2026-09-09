# Demo recording for the README, rendered with vhs (https://github.com/charmbracelet/vhs)
# by .github/workflows/demo.yml. Syntax verified against the vhs v0.12.0 README on
# 2026-09-09; Set Columns and Set Rows need v0.12.0 or later.
#
# The trustdiff binary must be on PATH. Local run: vhs docs/demo.tape

Output docs/demo.gif

Require trustdiff

Set Shell bash
Set FontSize 16
Set Columns 100
Set Rows 36
Set Padding 20
Set TypingSpeed 40ms

# Warm the cache off camera. The recorded runs then answer from disk, so the demo
# shows the tool rather than the network, and a rate-limited registry (the npm
# downloads API answers 429 to shared CI addresses often enough to matter) delays
# this hidden run instead of timing the recording out.
Hide
Type "trustdiff check npm:express@4.19.2 pypi:requests cargo:serde >/dev/null 2>&1; trustdiff check npm:flatmap-stream@0.1.1 >/dev/null 2>&1; echo CACHE-WARMED"
Enter
# Wait on a sentinel the command prints rather than on the prompt, whose shape
# depends on the shell vhs starts.
Wait+Screen@300s /CACHE-WARMED/
Type "clear"
Enter
Sleep 500ms
Show

# The three cards of the 0.1.0 acceptance scenario.
Type "trustdiff check npm:express@4.19.2 pypi:requests cargo:serde"
Sleep 500ms
Enter
# The summary line is the last thing the report prints.
Wait+Screen@120s /Exit code/
Sleep 5s

Type "clear"
Enter
Sleep 500ms

# The package behind the 2018 event-stream backdoor: a blocking finding and exit code 1.
Type "trustdiff check npm:flatmap-stream@0.1.1"
Sleep 500ms
Enter
Wait+Screen@120s /Exit code/
Sleep 6s
