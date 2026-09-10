# Demo recording for the README, rendered with vhs (https://github.com/charmbracelet/vhs)
# by .github/workflows/demo.yml.
#
# The trustdiff binary must be on PATH and the cache must already be warm. The
# workflow warms it in the step before this one; locally, run the same command once
# before recording.
#
# Nine runs across two days produced no file at all before one produced this. The
# cause was the vhs version, not the tape: v0.12.0, released 2026-09-09, prints that
# it is creating the GIF, exits 0 and writes nothing on an ubuntu-24.04 runner,
# whatever the tape contains. v0.11.0 records the same tape without complaint. The
# workflow pins it and says so, and it is reported upstream as
# charmbracelet/vhs#787.
#
# Three other things were changed along the way and none of them was the cause. They
# are kept because each is an improvement on its own, and listed here so nobody
# spends a day re-testing them:
#
#   Set Columns and Set Rows, which arrived in v0.12.0, gave way to Width and Height,
#   which vhs has always had.
#
#   ffmpeg is missing from the runner image and vhs does not check for it, so the
#   workflow installs it. It would have been the next failure.
#
#   A Hide block warmed the cache off camera. That belongs in the job rather than in
#   the recording, and it is there now.

Output docs/demo.gif

Require trustdiff

Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 700
Set Padding 20
Set TypingSpeed 40ms

# The acceptance scenario of docs/PLAN.md task 1.15: three packages, three verdicts.
Type "trustdiff check npm:express@4.19.2 pypi:requests cargo:serde"
Sleep 500ms
Enter
# The summary line is the last thing the report prints.
Wait+Screen@300s /Exit code/
Sleep 6s
