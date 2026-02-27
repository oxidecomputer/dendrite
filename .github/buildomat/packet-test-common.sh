export RUST_BACKTRACE=1

source .github/buildomat/common.sh
source .github/buildomat/linux.sh

wd=`pwd`
export WS=$wd
MODEL_STARTUP_TIMEOUT=${MODEL_STARTUP_TIMEOUT:=5}
STARTUP_TIMEOUT=${STARTUP_TIMEOUT:=120}

BUILD_FEATURES=tofino_asic

CODEGEN_FEATURES=--multicast
SWADM_FEATURES="--features=multicast"

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
if [[ $NOBUILD -ne 1 ]]; then
    cargo build --features=$BUILD_FEATURES --bin dpd --bin swadm
    cargo xtask codegen --stages $TOFINO_STAGES $CODEGEN_FEATURES
fi

banner "Test"
sudo -E ./tools/veth_setup.sh
id=`id -un`
gr=`id -gn`
sudo -E mkdir -p /work
sudo -E chown $id:$gr /work
sudo -E ./tools/run_tofino_model.sh &> /work/simulator.log &
sleep $MODEL_STARTUP_TIMEOUT
sudo -E ./tools/run_dpd.sh -m 127.0.0.1 &> /work/dpd.log &
echo "waiting for dpd to come online"
set +o errexit

SLEEP_TIME=5
iters=$(( $STARTUP_TIMEOUT / $SLEEP_TIME ))
while [ 1 ] ; do
	./target/debug/swadm --host '[::1]' build-info 2> /dev/null
	if [ $? == 0 ]; then
		break
	fi
	iters=$(($iters - 1))
	if [ $iters = 0 ]; then
		echo "dpd failed to come online in $STARTUP_TIMEOUT seconds"
		exit 1
	fi
	sleep $SLEEP_TIME
done
set -o errexit

banner "Links"

./target/debug/swadm --host '[::1]' link ls || echo "failed to list links"

banner "swadm Checks"

pushd swadm

DENDRITE_TEST_HOST='[::1]' \
    DENDRITE_TEST_VERBOSITY=3 \
    cargo test \
    --no-fail-fast \
    $SWADM_FEATURES \
    --test \
    counters \
    -- \
    --ignored

popd

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
    --features $BUILD_FEATURES \
    --no-fail-fast \
    $TESTNAME \
    -- \
    --ignored
