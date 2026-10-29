#!/bin/bash
#:
#: name = "test-proptest"
#: variety = "basic"
#: target = "helios-3.0"
#: rust_toolchain = true
#: output_rules = [
#:   "/work/proptest-regressions/**/*",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

source .github/buildomat/common.sh

NEXTEST_VERSION='0.9.97'
nextest_tmp="$(mktemp -d)"
trap 'rm -rf "${nextest_tmp}"' EXIT
nextest_tar="${nextest_tmp}/nextest.tar.gz"
curl -sSfL --retry 10 -o "${nextest_tar}" \
	"https://get.nexte.st/${NEXTEST_VERSION}/illumos"
mkdir -p "${CARGO_HOME:-${HOME}/.cargo}/bin"
tar -xzf "${nextest_tar}" -C "${CARGO_HOME:-${HOME}/.cargo}/bin"

status=0
pushd dpd-types/versions
PROPTEST_CASES=1000000 cargo nextest run --lib proptests || status=$?
if [[ -d proptest-regressions ]]; then
	mkdir -p /work/proptest-regressions/dpd-types-versions
	cp -r proptest-regressions/. /work/proptest-regressions/dpd-types-versions/
fi
popd

exit "${status}"
