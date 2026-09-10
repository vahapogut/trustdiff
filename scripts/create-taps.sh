#!/bin/sh
# Create and seed the Homebrew tap and the Scoop bucket that goreleaser publishes to.
#
# This is the one-time setup that docs/releasing.md describes, in one command. It
# creates github.com/<owner>/homebrew-tap and github.com/<owner>/scoop-bucket, both
# public, and gives each an initial commit holding a README and the project's
# LICENSE. Nothing else.
#
# Two things are deliberate about that.
#
# The commit itself matters. goreleaser writes its file through the GitHub contents
# API, which will happily initialise a repository that has no commits, but only
# when the branch it is configured to push to is already that repository's default
# branch. Both blocks in .goreleaser.yaml name "main" explicitly, so a repository
# whose default branch is anything else would fail on the first release with "could
# not get ref". One README commit removes the dependency entirely.
#
# The directories are NOT seeded. Casks/ and bucket/ are created by goreleaser on
# the first publish, and an empty directory cannot be committed anyway without a
# placeholder file. A placeholder would be wrong in the bucket: Scoop counts what a
# bucket holds with a recursive listing under bucket/ that includes hidden files and
# is not filtered to *.json, so a .gitkeep there would make "scoop bucket list"
# report two manifests where there is one. Keeping README and LICENSE at the root is
# what Scoop expects.
#
# It does not create the token. A fine grained personal access token cannot be
# minted through the API, by design: it would be a credential creating a credential.
# The script prints what to do about that at the end.
#
# Run it from the root of a trustdiff checkout, with the gh command line signed in
# as the account that will own the two repositories:
#
#   sh scripts/create-taps.sh
#
# It is safe to run twice. A repository that already exists is left alone, and so is
# a file that is already committed.

set -eu

owner="${TAP_OWNER:-vahapogut}"
project_url="https://github.com/${owner}/trustdiff"

if [ ! -f LICENSE ] || [ ! -f .goreleaser.yaml ]; then
	echo "run this from the root of a trustdiff checkout: LICENSE and .goreleaser.yaml are read from here" >&2
	exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
	echo "the gh command line is not on PATH; install it and run 'gh auth login' first" >&2
	exit 2
fi
if ! gh auth status >/dev/null 2>&1; then
	echo "gh is not signed in; run 'gh auth login' first" >&2
	exit 2
fi

license=$(cat LICENSE)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# seed <repo> <generated file name> <description>
seed() {
	repo=$1
	generated=$2
	description=$3

	# The guard is on a commit rather than on the repository, because those are
	# different states and only one of them is finished. A run that created the
	# repository and then failed to push leaves it with no commit, which is exactly
	# the state goreleaser cannot write into, and guarding on existence alone would
	# make every later run skip it and call it done.
	if gh api "repos/${owner}/${repo}/commits" --jq '.[0].sha' >/dev/null 2>&1; then
		echo "${owner}/${repo} already exists and has a commit, leaving it alone"
		return 0
	fi

	if gh repo view "${owner}/${repo}" >/dev/null 2>&1; then
		echo "${owner}/${repo} exists but has no commit; seeding it"
	else
		echo "creating ${owner}/${repo}"
		gh repo create "${owner}/${repo}" --public --description "${description}"
	fi

	dir="${work}/${repo}"
	mkdir -p "${dir}"
	printf '%s\n' "${license}" >"${dir}/LICENSE"
	readme "${repo}" >"${dir}/README.md"

	git -C "${dir}" init -q -b main
	git -C "${dir}" add -A
	git -C "${dir}" commit -q -m "Seed the repository goreleaser publishes ${generated} into"
	git -C "${dir}" remote add origin "https://github.com/${owner}/${repo}.git"
	git -C "${dir}" push -q -u origin main
	echo "seeded https://github.com/${owner}/${repo} with main as its default branch"
}

readme() {
	case $1 in
	homebrew-tap)
		cat <<-EOF
			# homebrew-tap

			The Homebrew tap for [trustdiff](${project_url}), a single binary that finds trust regressions in a project's dependency tree before they land.

			\`\`\`sh
			brew install --cask ${owner}/tap/trustdiff
			\`\`\`

			The cask is named in full on purpose. Since Homebrew 6.0 a tap that is not one of Homebrew's own has to be trusted before its code will run, and installing a fully qualified name trusts that one cask and nothing else. Tapping first and then installing the short name needs a separate \`brew trust --cask ${owner}/tap/trustdiff\`, and \`brew trust ${owner}/tap\` accepts everything this tap will ever hold, which is more than anyone should hand a third party.

			## What is in here

			One generated file, \`Casks/trustdiff.rb\`, beside this README and the license. It is written by [goreleaser](https://goreleaser.com) from \`.goreleaser.yaml\` in the trustdiff repository and committed here by the release workflow every time a version tag is pushed. Nothing here is edited by hand, so a pull request against the cask would be overwritten by the next release. Changes belong in [${owner}/trustdiff](${project_url}), where the cask is generated from.

			A release candidate, meaning a tag with a suffix such as \`v1.2.3-rc.1\`, is deliberately not published here. That is what makes one safe to push: it exercises the whole release pipeline without moving what \`brew upgrade\` would hand to somebody.

			## Verifying a download yourself

			The cask installs the same archive the releases page serves, and Homebrew checks it against the sha256 recorded in the cask. That is a real check, but the sha256 and the archive it describes were produced by the same job, so it proves the download was not altered in transit and not much more.

			Every trustdiff release also ships \`checksums.txt\`, a cosign signature over it, an SBOM per archive and GitHub build provenance. To check the chain rather than trust this repository, download the archive from the [releases page](${project_url}/releases) and follow the three steps in the trustdiff README. They verify the signature against the release workflow's own identity, which is the part a tap cannot do for you.

			## License

			trustdiff is Apache-2.0, and so is the cask generated from it. See [LICENSE](LICENSE).
		EOF
		;;
	scoop-bucket)
		cat <<-EOF
			# scoop-bucket

			The Scoop bucket for [trustdiff](${project_url}), a single binary that finds trust regressions in a project's dependency tree before they land.

			\`\`\`powershell
			scoop bucket add trustdiff https://github.com/${owner}/scoop-bucket
			scoop install trustdiff
			\`\`\`

			## What is in here

			One generated file, \`bucket/trustdiff.json\`, beside this README and the license at the repository root, which is where they belong because Scoop counts everything under \`bucket/\`. It is written by [goreleaser](https://goreleaser.com) from \`.goreleaser.yaml\` in the trustdiff repository and committed here by the release workflow every time a version tag is pushed. The architecture table inside it, one entry per Windows build with its download URL and its sha256, is generated from that release's archives, so a hand edit would go stale on the next release and would be overwritten anyway. Changes belong in [${owner}/trustdiff](${project_url}).

			A release candidate, meaning a tag with a suffix such as \`v1.2.3-rc.1\`, is deliberately not published here, so pushing one exercises the release pipeline without moving what \`scoop update\` would hand to somebody.

			## Verifying a download yourself

			Scoop checks the archive against the sha256 in the manifest. Both were produced by the same job, so that proves the download arrived intact and not much more.

			Every trustdiff release also ships \`checksums.txt\`, a cosign signature over it, an SBOM per archive and GitHub build provenance. To check the chain rather than trust this repository, download the archive from the [releases page](${project_url}/releases) and follow the three verification steps in the trustdiff README, which include the PowerShell spelling of the checksum comparison.

			## License

			trustdiff is Apache-2.0, and so is the manifest generated from it. See [LICENSE](LICENSE).
		EOF
		;;
	esac
}

seed homebrew-tap trustdiff.rb "Homebrew tap for trustdiff. Generated by goreleaser on every release tag."
seed scoop-bucket trustdiff.json "Scoop bucket for trustdiff. Generated by goreleaser on every release tag."

if gh secret list --repo "${owner}/trustdiff" 2>/dev/null | grep -q '^TAP_GITHUB_TOKEN'; then
	cat <<-EOF

		Both repositories are ready and TAP_GITHUB_TOKEN is already stored on
		${owner}/trustdiff, so the next stable tag publishes the cask and the manifest
		by itself. Nothing else to do.

		Mint a replacement the same way when the token expires, then store it again
		with: gh secret set TAP_GITHUB_TOKEN --repo ${owner}/trustdiff
	EOF
	exit 0
fi

cat <<EOF

Both repositories are ready. One thing is left, and it needs a browser:

  1. Create a fine grained personal access token at
     https://github.com/settings/personal-access-tokens/new
     Resource owner: ${owner}
     Repository access: only select repositories, and pick exactly
       ${owner}/homebrew-tap and ${owner}/scoop-bucket
     Repository permissions: Contents, Read and write. Nothing else.
     Expiry: whatever you are willing to rotate.

  2. Store it on the trustdiff repository as the secret the release job reads:
       gh secret set TAP_GITHUB_TOKEN --repo ${owner}/trustdiff
     and paste the token when it asks. It is never echoed and never stored here.

The next version tag then publishes the cask and the manifest by itself. Nothing
in .goreleaser.yaml has to change: both publishers already test for the secret and
skip the upload when it is absent.
EOF
