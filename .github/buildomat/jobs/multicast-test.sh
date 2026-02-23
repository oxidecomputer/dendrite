#!/bin/bash
#:
#: name = "multicast-test"
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
####   - NOBUILD=1          Don't build sidecar.p4 (in case you've already
####                        built it)
####
#### <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

export RUST_BACKTRACE=1

set -o errexit
set -o pipefail
set -o xtrace

source .github/buildomat/packet-test-common.sh
