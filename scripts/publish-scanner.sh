#!/bin/sh
# Do the one-time npm setup for @trustdiff/bun-scanner, in one command.
#
# docs/releasing.md section 9 explains why these steps exist. This script does the
# two that can be scripted and checks the one that cannot:
#
#   1. The npm organisation. NOT scriptable. Organisations are created on
#      npmjs.com and nowhere else, and the scope has to be an organisation rather
#      than a personal one because npm only ever gives an account the scope
#      matching its own name. The script checks and stops with a link.
#   2. The first version, published by hand. Trusted publishing cannot create a
#      package that does not exist, so this one publish has to come from somebody
#      who can answer a two-factor prompt. The script runs it.
#   3. The trusted publisher, so every later version comes from the workflow and
#      no npm credential ever lives in the repository. The script runs it.
#
# Run it from the root of a trustdiff checkout, signed in to npm:
#
#   npm login
#   sh scripts/publish-scanner.sh
#
# It is safe to run twice. A version that is already published is left alone, and
# so is a trusted publisher that is already configured.
#
# Nothing here reads, stores or prints a credential. npm asks for the one time
# password itself, in its own prompt.

set -eu

repo="${TRUSTDIFF_REPO:-vahapogut/trustdiff}"
workflow="npm-publish.yml"
dir="integrations/bun-scanner"

if [ ! -f "${dir}/package.json" ]; then
	echo "run this from the root of a trustdiff checkout: ${dir}/package.json is read from here" >&2
	exit 2
fi
for tool in npm node; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		echo "${tool} is not on PATH" >&2
		exit 2
	fi
done

name=$(node --print "require('./${dir}/package.json').name")
version=$(node --print "require('./${dir}/package.json').version")
scope=${name%%/*}
org=${scope#@}
echo "package: ${name}@${version}"

# npm 11.15.0 or newer for "npm trust"; that is the highest floor of the three.
npm_version=$(npm --version)
case $(printf '%s\n11.15.0\n' "${npm_version}" | sort -V | head -1) in
11.15.0) ;;
*)
	echo "npm ${npm_version} is too old; 'npm trust' needs 11.15.0 or newer." >&2
	echo "  npm install --global npm@latest" >&2
	exit 2
	;;
esac

if ! who=$(npm whoami 2>/dev/null); then
	echo "not signed in to npm. Run 'npm login' first, then this script again." >&2
	exit 2
fi
echo "signed in as: ${who}"

# Two-factor authentication is checked before anything is published, not when the
# publisher is configured, because step 3 needs it and step 2 does not. Finding
# out at the end would leave the package published and the workflow still unable
# to touch it, which is the one half-done state worth avoiding.
tfa=$(npm profile get --json 2>/dev/null | node --print "JSON.parse(require('fs').readFileSync(0,'utf8')).tfa ? 'on' : 'off'" 2>/dev/null || echo unknown)
if [ "${tfa}" = "off" ]; then
	cat >&2 <<-EOF

		Two-factor authentication is off on ${who}, and "npm trust" refuses to run
		without it.

		It has to be a passkey or a security key. npm stopped accepting an
		authenticator app for a new enrolment: as of 2026-09-10 "npm profile
		enable-2fa" answers a request to add one with "Adding a new TOTP 2FA is no
		longer supported". The methods it does take are WebAuthn ones, which means a
		passkey through Windows Hello, Touch ID or Face ID, or a hardware key such as
		a YubiKey.

		  https://www.npmjs.com/settings/${who}/tfa

		Keep the recovery codes somewhere you will still have them if the device is
		lost. Then run this script again.
	EOF
	exit 2
fi
echo "two-factor authentication: ${tfa}"

# 1. The organisation, which is the one step nothing can do for you.
if ! npm org ls "${org}" >/dev/null 2>&1; then
	cat >&2 <<-EOF

		The npm organisation "${org}" is not one this account can see, so the scope
		${scope} cannot be published to yet.

		Create it at https://www.npmjs.com/org/create
		  Name: ${org}          (the name becomes the scope, so it must be exactly this)
		  Plan: the free one, "unlimited public packages"

		Turn on two-factor authentication on the account first: "npm trust" requires it.
		npm no longer accepts an authenticator app for a new enrolment. As of
		2026-09-10 "npm profile enable-2fa" answers a request to add one with "Adding
		a new TOTP 2FA is no longer supported", and the only methods it takes are
		WebAuthn ones: a passkey through Windows Hello, Touch ID or Face ID, or a
		hardware key such as a YubiKey. Add one at
		https://www.npmjs.com/settings/<your-account>/tfa and keep the recovery codes.

		Then run this script again.
	EOF
	exit 2
fi
echo "organisation ${org}: visible to this account"

# 2. The first publish. Every later version comes from the workflow.
if npm view "${name}@${version}" version >/dev/null 2>&1; then
	echo "${name}@${version} is already published, leaving it alone"
else
	echo
	echo "what would be published:"
	(cd "${dir}" && npm pack --dry-run)
	echo
	printf 'publish %s@%s now? [y/N] ' "${name}" "${version}"
	read -r answer
	case "${answer}" in
	y | Y | yes | YES) ;;
	*)
		echo "stopped without publishing"
		exit 1
		;;
	esac
	# --provenance=false is not optional. package.json sets publishConfig.provenance
	# for the workflow, and npm generates provenance only on GitHub Actions and
	# GitLab CI; anywhere else it aborts the publish rather than skipping it. A flag
	# on the command line wins over publishConfig, which is what makes this work.
	# "npm publish --dry-run" does not warn, because it returns before that check.
	(cd "${dir}" && npm publish --access public --provenance=false)
	echo "published ${name}@${version} without provenance; every later version has it"
fi

# 3. The trusted publisher, so the workflow can take over.
echo
echo "pointing ${name} at ${repo} .github/workflows/${workflow}"
# The output and the exit status are kept apart on purpose. npm trust list writes
# to stderr and exits non-zero when there is nothing configured yet, and an earlier
# version of this discarded both, so the "already configured" branch could never be
# taken and a second run would try to create the configuration again.
if trust_out=$(npm trust list "${name}" 2>&1) && printf '%s' "${trust_out}" | grep -q "${workflow}"; then
	echo "already configured, leaving it alone"
else
	# The package is named rather than inferred: npm would otherwise read the
	# package.json of whatever directory this runs in, and that is the repository
	# root here, not the scanner.
	#
	# --allow-stage-publish is not optional either. npm refuses to create a
	# configuration without a permission flag: trust-cmd.js throws "At least one
	# permission flag is required". Staging is the one this project chooses, because
	# the workflow runs "npm stage publish" and nothing else, and because a person
	# between a build and a version the world can install is the whole argument this
	# tool makes. docs/releasing.md section 9 says why at length.
	npm trust github "${name}" --repo "${repo}" --file "${workflow}" --allow-stage-publish
	echo "configured"
fi

cat <<EOF

Done. From here on, bump "version" in ${dir}/package.json in the commit that
carries the trustdiff release it belongs to, and the version tag stages it.

Staged, not published: this configuration was created with staging permission and
not direct publish, which is a choice rather than a default, and one this project
makes on purpose. To release a staged version:

  npm stage list ${name}
  npm stage download <stage-id>   # read what the job built
  npm stage approve <stage-id>    # make it public

One thing worth doing now, on the package settings page on npmjs.com: restrict
token based publishing, so that a leaked classic token cannot publish a version
the workflow did not build.
EOF
