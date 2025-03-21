#!/bin/bash
#:
#: name = "test"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = true
#: access_repos = [
#:   "oxidecomputer/p4",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

source .github/buildomat/common.sh
source .github/buildomat/illumos.sh

banner "copyrights"
./tools/check_copyrights.sh || exit 1

banner "clippy"
for feat in tofino_stub tofino_asic softnpu chaos
do
	cargo clippy --features $feat -- --deny warnings
done

banner "fmt"
cargo fmt -- --check

banner "test"
for feat in tofino_stub tofino_asic softnpu chaos
do
    cargo test --features $feat
done
