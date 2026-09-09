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

# The three cards of the 0.1.0 acceptance scenario, against the live registries.
Type "trustdiff check npm:express@4.19.2 pypi:requests cargo:serde"
Sleep 500ms
Enter
# The summary line is the last thing the report prints.
Wait+Screen@60s /Exit code/
Sleep 5s

Type "clear"
Enter
Sleep 500ms

# The package behind the 2018 event-stream backdoor: a blocking finding and exit code 1.
Type "trustdiff check npm:flatmap-stream@0.1.1"
Sleep 500ms
Enter
Wait+Screen@60s /Exit code/
Sleep 6s
