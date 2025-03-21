#!/bin/bash
#:
#: name = "image"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = true
#: output_rules = [
#:   "/out/*",
#:   "/out/p4c-diags/logs/*",
#:   "/out/p4c-diags/graphs/*"
#: ]
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-stub.tar.gz"
#: from_output = "/out/dendrite-stub.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-stub.sha256.txt"
#: from_output = "/out/dendrite-stub.sha256.txt"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-asic.tar.gz"
#: from_output = "/out/dendrite-asic.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-asic.sha256.txt"
#: from_output = "/out/dendrite-asic.sha256.txt"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-asic-console.tar.gz"
#: from_output = "/out/dendrite-asic-console.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-asic-console.sha256.txt"
#: from_output = "/out/dendrite-asic-console.sha256.txt"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-softnpu.tar.gz"
#: from_output = "/out/dendrite-softnpu.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-softnpu.sha256.txt"
#: from_output = "/out/dendrite-softnpu.sha256.txt"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-global.tar.gz"
#: from_output = "/out/dendrite-global.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-global.sha256.txt"
#: from_output = "/out/dendrite-global.sha256.txt"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-global-console.tar.gz"
#: from_output = "/out/dendrite-global-console.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "dendrite-global-console.sha256.txt"
#: from_output = "/out/dendrite-global-console.sha256.txt"
#:
#: [[publish]]
#: series = "bin"
#: name = "swadm"
#: from_output = "/out/swadm"
#:
#: [[publish]]
#: series = "bin"
#: name = "swadm.sha256.txt"
#: from_output = "/out/swadm.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

source .github/buildomat/common.sh
source .github/buildomat/illumos.sh

# Copy file from our local working directory into the /out directory, where
# buildomat can retrieve for archiving.
# usage: archive <source stem> <dest stem> <suffix>
function archive {
    mv out/$1$3 /out/$2$3
    digest -a sha256 /out/$2$3 > /out/$2.sha256.txt
}

pfexec mkdir -p /out
pfexec chown "$UID" /out

banner "P4 Codegen"
# Add gcc-12 so the p4 compiler can find cpp
# The tofino2 has 20 stages, but the current sidecar.p4 will fit into 14.  We
# add the "--stages 14" here to detect if/when the program grows beyond that
# limit.  It's not necessarily a problem if we grow, but given the limited space
# on the ASIC, we want to grow deliberatately and thoughtfully.
PATH=/opt/gcc-12/bin:$PATH cargo xtask codegen --stages 14

# Preserve all the diagnostics spit out by the compiler
mkdir -p /out/p4c-diags
cp -r target/proto/opt/oxide/dendrite/sidecar/pipe/logs /out/p4c-diags/
cp -r target/proto/opt/oxide/dendrite/sidecar/pipe/graphs /out/p4c-diags/

# Build the binaries that are common across all asic varieties
banner build common
export SDE=/opt/oxide/tofino_sde
ptime -m cargo build --release --verbose --bin swadm --bin tfportd --bin uplinkd
cp target/release/swadm /out
digest -a sha256 /out/swadm > /out/swadm.sha256.txt

cp target/release/swadm /out
digest -a sha256 /out/swadm > /out/swadm.sha256.txt

# Build the `dpd` binary, and package / archive the result.
#
# Arguments:
#   1. The feature name for the provided package name, e.g., `tofino_asic`
#   2. An optional `--with-console` flag, to enable the `tokio-console` feature
#   of `dpd`.
function build() {
    local FEATURE="$1"
    NAME="$(echo $FEATURE | sed "s/tofino_//")"
    if [ "$2" = "--with-console" ]; then
        echo "building with tokio-console feature"
        DPD_FEATURES="$FEATURE tokio-console"
        LOCAL_ARCHIVE_SUFFIX="$NAME-console"
        GLOBAL_ARCHIVE_SUFFIX="global-console"
    else
        DPD_FEATURES="$FEATURE"
        LOCAL_ARCHIVE_SUFFIX="$NAME"
        GLOBAL_ARCHIVE_SUFFIX="global"
    fi
    banner build "$NAME"
    ptime -m cargo build --release --verbose --features "$DPD_FEATURES" --bin dpd

    banner package "$NAME"
    ptime -m cargo xtask dist --format omicron --release --features "$FEATURE"

    if [ "$NAME" = "asic" ]; then
	    echo "building helios tarball"
	    ptime -m cargo xtask dist --format global --release
        mv dendrite-global.tar.gz "out/dendrite-$GLOBAL_ARCHIVE_SUFFIX.tar.gz"
	    archive "dendrite-$GLOBAL_ARCHIVE_SUFFIX" "dendrite-$GLOBAL_ARCHIVE_SUFFIX" .tar.gz
    fi

    banner archive "$NAME"
    archive dendrite "dendrite-$LOCAL_ARCHIVE_SUFFIX" .tar.gz
}

for FEATURE in tofino_stub tofino_asic softnpu
do
    build "$FEATURE"
    if [ "$FEATURE" = "tofino_asic" ]; then
        build "$FEATURE" --with-console
    fi
done

ls -lR /out/
