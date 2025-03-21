#!/bin/bash
#:
#: name = "linux"
#: variety = "basic"
#: target = "ubuntu-22.04"
#: rust_toolchain = true
#: output_rules = [
#:   "/out/*",
#:   "/work/swadm",
#:   "/work/swadm.sha256.txt",
#:   "/work/dpd",
#:   "/work/dpd.sha256.txt",
#: ]
#:
#: [[publish]]
#: series = "linux-bin"
#: name = "swadm"
#: from_output = "/work/swadm"
#:
#: [[publish]]
#: series = "linux-bin"
#: name = "swadm.sha256.txt"
#: from_output = "/work/swadm.sha256.txt"
#:
#: [[publish]]
#: series = "linux-bin"
#: name = "dpd"
#: from_output = "/work/dpd"
#
#: [[publish]]
#: series = "linux-bin"
#: name = "dpd.sha256.txt"
#: from_output = "/work/dpd.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

source .github/buildomat/common.sh
source .github/buildomat/linux.sh

banner "Packages"
sudo apt update -y
sudo apt install -y libpcap-dev libclang-dev libssl-dev

export SDE=/opt/oxide/tofino_sde

banner "Build"
cargo build --features=tofino_asic --bin dpd
cargo build --release --features=tofino_stub --bin dpd --bin swadm

cp target/release/dpd /work
digest /work/dpd > /work/dpd.sha256.txt

cp target/release/swadm /work
digest /work/swadm > /work/swadm.sha256.txt

banner "Artifacts"
sudo mkdir -p /out
sudo chown "$UID" /out
