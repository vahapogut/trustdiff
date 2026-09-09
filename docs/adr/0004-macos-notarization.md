# ADR 0004: Ship the macOS binaries unsigned, and say so where it bites

Date: 2026-09-10
Status: accepted

## Context

Every trustdiff release ships two macOS archives. They carry a bare Mach-O executable,
not an application bundle and not an installer package. They are signed the way the
rest of the release is signed: `checksums.txt` carries a cosign keyless signature, each
archive has an SPDX SBOM, and the whole build has SLSA provenance from the tagged
workflow. None of that is an Apple code signature, and macOS knows nothing about any of
it.

Apple's own check is Gatekeeper, and it applies only to a file carrying the
`com.apple.quarantine` extended attribute. That attribute is set by the program that
fetched the file and carried onto what comes out of it by the program that unpacked it,
so the question is not "is this binary signed" but "how did it arrive":

| How a person gets trustdiff on macOS | Quarantined | What they see today |
|---|---|---|
| `go install` | no | nothing |
| `curl`, `wget`, `scp`, a CI step | no | nothing |
| Browser download, unpacked with `tar` in a shell | no | nothing |
| Browser download, unpacked by Finder's Archive Utility | yes | the first run is refused |
| `brew install --cask` from our tap | yes | the first run is refused |

Browsers mark what they download and Unix fetchers do not; `tar` from a shell does not
propagate the mark to what it extracts and Finder's Archive Utility does. That fork is
the whole user experience for the download route, and it lands the way the README's own
instructions point, because those instructions are shell commands.

The last two rows are the problem, and it is a real one: it is the most common bad
first impression a Go command line tool gives on macOS. The binary is killed on exec,
so a shell prints something like `killed  trustdiff` with no button to click, and the
way out is `xattr -d com.apple.quarantine`, which is a thing nobody should have to
know. Since macOS 15 there is no Control-click override either; the only supported
route is System Settings.

The Homebrew row is worth stating plainly, because the comfortable assumption is the
opposite. Homebrew fetches with curl, which marks nothing, and then marks the download
itself on purpose before propagating that onto every file it stages. That is exactly why
`--no-quarantine` existed, and that flag was deprecated and then removed rather than
kept: Homebrew's position is that bypassing Gatekeeper is not a package manager's call
to make on a user's behalf, which is also this project's position. So the tap does not
avoid the wall, and a `binary` stanza does not either, because the symlink it creates
points at a staged file that carries the mark.

One thing that is not a problem: Apple silicon refuses to execute native arm64 code
carrying no signature at all, but Go's linker ad-hoc signs every darwin/arm64 binary it
builds, and this project builds with `CGO_ENABLED=0` and the internal linker. So the
arm64 archive is not rejected for being unsigned outright; it is rejected only when it
carries the mark, which is the case above.

None of these rows was tested on a Mac; no Mac was available. They are read off Apple's
and Homebrew's own documentation, and off Homebrew's removal of that flag.

Fixing it properly means enrolling in the Apple Developer Program at 99 USD per year,
holding a Developer ID Application certificate that only the account holder can create,
and submitting each build to Apple's notary service with `xcrun notarytool`. goreleaser
2.18.1 supports exactly this in its open source edition through the `notarize.macos`
block, which signs in process with a Go library rather than shelling out to Apple's own
tools, so it runs on the Linux runner this project already releases from and the tooling
is not the obstacle. A configuration block and five repository secrets would do it: the
exported certificate, its password, the App Store Connect key and that key's two
identifiers. All of the above was verified on 2026-09-10 against Apple's developer
documentation, Apple's Technote 3147 on migrating off `altool`, and goreleaser's own
customization pages.

Two facts decided this, and neither is about the money.

The first is what notarization would not fix. Double clicking a command line tool in
Finder stays broken whether it is notarized or not: Finder hands the executable to
Terminal as a document, and Gatekeeper's document logic always blocks it. Apple
documents this as a known bug and offers two ways out, embedding the tool in an
application or shipping an installer package, neither of which is a thing this project
wants to become. So notarization buys a clean first run in a terminal, and nothing
outside a terminal.

That narrows what notarization is for, but it does not make it small: two of the five
rows above are exactly what it would fix, and one of them is the route the README
recommends to anyone on macOS who does not have Go installed.

The second thing is what notarization would cost this particular pipeline. `.goreleaser.yaml`
is built for byte-reproducible archives: `mod_timestamp`, `builds_info.mtime` and
`SOURCE_DATE_EPOCH` are all set for that reason and all commented as such. A Developer
ID signature is embedded inside the Mach-O and normally carries a secure timestamp from
Apple's timestamp authority, which is not deterministic. Signing would very likely mean
the two macOS archives stop reproducing byte for byte while Linux and Windows keep
doing so.

That is the trade in front of a tool whose entire pitch is that you should be able to
check what you are installing. Reproducibility is something a reader can verify alone,
from source, forever. An Apple signature is something a reader takes on Apple's word,
that expires, and that says nothing about what is in the binary.

## Decision

Do not sign or notarize the macOS binaries. Ship them as they are, and treat the
first-run refusal as something to explain rather than something to hide.

Three alternatives were weighed. Notarizing was rejected for the two reasons above.
Stripping the quarantine attribute automatically, which goreleaser documents as a
`hooks.post.install` calling `xattr`, was rejected outright: a tool that exists to
report supply chain risk must not disable a macOS security check on the user's behalf,
and a cask that did it would be doing exactly what a malicious cask would do. Saying
nothing was rejected because the wall is real and the workaround is not guessable.

What is done instead: the README carries the table above, so a macOS user can see
before installing whether they will meet the wall, and the one command that clears it.
The cask carries no `caveats` stanza today. That is worth revisiting, because a
Homebrew user does hit this and Homebrew is the one route where a message could be put
in front of them at the moment it matters.

## Consequences

The release pipeline stays as it is. No Apple account, no certificate to rotate, no
`.p12` and no App Store Connect key in the repository's secrets, and five fewer secrets
is itself worth something for a project of this kind. All six archives keep reproducing
byte for byte.

A macOS user who downloads from the releases page in a browser, or installs from the
tap, still meets the refusal on first run. That is now a documented step rather than a
surprise, but it is still a worse experience than a notarized binary would give, and it
is the price of this decision. It is also the part most likely to be raised as an issue,
which is the signal to reopen this.

The official `homebrew/cask` repository is closed to this project. Casks that fail
Gatekeeper checks have been disabled there since 2026-09-01, so an unsigned binary
cannot go in. The personal tap at `vahapogut/homebrew-tap` is unaffected: Homebrew's
maintainers are explicit that software in your own tap does not have to be signed.

Revisit this if any of three things changes. If getting into the official cask
repository becomes a goal, signing is the entry fee and this ADR is superseded. If
macOS ever starts quarantining files that arrive by `curl` or refusing unsigned
binaries outright, the calculation moves from one row of that table to all of them. And
if goreleaser or Apple make a Developer ID signature deterministic, the reproducibility
argument disappears and only the cost is left, which is a much easier question.
