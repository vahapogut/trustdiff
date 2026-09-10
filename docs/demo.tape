# Demo recording for the README, rendered with vhs (https://github.com/charmbracelet/vhs)
# by .github/workflows/demo.yml.
#
# The trustdiff binary must be on PATH and the cache must already be warm. The
# workflow warms it in the step before this one; locally, run the same command once
# before recording.
#
# This tape is deliberately as small as vhs will let it be, because seven runs across
# two days produced no file at all while it was larger. Three things were tried and
# ruled out, and they are worth leaving written down so nobody repeats them:
#
#   Set Columns and Set Rows, which arrived in vhs v0.12.0 on the same day the first
#   run failed, are gone in favour of Width and Height. Not the cause.
#
#   ffmpeg is missing from the runner image and vhs does not check for it. The
#   workflow installs it now. Not the cause either, though it would have been next.
#
#   A Hide/Show block warmed the cache off camera. Frame capture is what Show turns
#   back on, so an empty frame set would look exactly like this: vhs prints that it
#   is creating the file, exits 0, and writes nothing. The warm-up moved into the
#   workflow and this tape no longer hides anything.

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
