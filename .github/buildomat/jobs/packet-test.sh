#!/bin/bash
#:
#: name = "packet-test"
#: variety = "basic"
#: target = "ubuntu-22.04"
#: rust_toolchain = true
#:
#: output_rules = [
#:   "/work/simulator.log",
#:   "/work/dpd.log",
#: ]
#:

#### >>>>>>>>>>>>>>>>>>>>>>>>>>>> Local Usage >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
####
#### The following environment variables are useful.
####
####   - JUST_TEST=1        Just runs the tests, skipping system prep.
####   - TESTNAME='$name'   Will just run the specified test.
####   - STARTUP_TIMEOUT=n  Seconds to wait for tofino-model/dpd to start.
####                        Defaults to 15.
####
#### <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

set -o errexit
set -o pipefail
set -o xtrace

source .github/buildomat/common.sh
source .github/buildomat/linux.sh

wd=`pwd`
export WS=$wd
STARTUP_TIMEOUT=${STARTUP_TIMEOUT:=15}

function cleanup {
    set +o errexit
    set +o pipefail
    cd $wd
    sudo -E pkill -9 dpd
    sudo -E pkill -9 tofino-model
    sudo -E ./tools/veth_teardown.sh
    stty sane
    # wait for daemons to die, if log file sizes change this can fail CI
    sleep 10
}
trap cleanup EXIT

if [[ $JUST_TEST -ne 1 ]]; then
    # See what hugepages was before starting
    sysctl vm.nr_hugepages
    # Make sure huge pages is enabled. This is required for running the SDE on
    # linux.
    sudo -E sysctl -w vm.nr_hugepages=128
    # Under some circumstances the sysctl may not completely work, so flush
    # the vm caches and retry.
    sudo -E sh -c 'echo 3 > /proc/sys/vm/drop_caches'
    sudo -E sysctl -w vm.nr_hugepages=128
    # See what hugepages is now. If this is zero and things go sideways later,
    # you'll know why.
    sysctl vm.nr_hugepages

    banner "Packages"
    sudo apt update -y
    sudo apt install -y \
        libpcap-dev \
        libclang-dev \
        libssl-dev \
        pkg-config \
        libcli-dev \
        sysvbanner
fi

export SDE=/opt/oxide/tofino_sde

banner "Build"
cargo build --features=tofino_asic --bin dpd --bin swadm
cargo xtask codegen

banner "Test"
sudo -E ./tools/veth_setup.sh
id=`id -un`
gr=`id -gn`
sudo -E mkdir -p /work
sudo -E chown $id:$gr /work
sudo -E ./tools/run_tofino_model.sh &> /work/simulator.log &
sleep $STARTUP_TIMEOUT
sudo -E ./tools/run_dpd.sh -m 127.0.0.1 &> /work/dpd.log &
sleep $STARTUP_TIMEOUT

banner "Links"

./target/debug/swadm -h '[::1]' link ls || echo "failed to list links"

banner "Packet Tests"

set +o errexit
set +o pipefail
stty sane
set -o errexit
set -o pipefail

pushd dpd-client

DENDRITE_TEST_HOST='[::1]' \
    DENDRITE_TEST_VERBOSITY=3 \
    cargo test \
    --features tofino_asic \
    --no-fail-fast \
    $TESTNAME \
    -- \
    --ignored
