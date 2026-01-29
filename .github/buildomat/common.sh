#!/bin/bash

# The tofino2 has 20 stages. Base sidecar.p4 needs 15 stages, and with
# multicast support it needs 18. Specifying the number of stages isn't strictly
# necessary, but it allows us to track when we exceed the current ceiling.
# The underlying intention is to grow deliberately and thoughtfully, given the
# limited space on the ASIC.
if [[ "${BUILD_FEATURES:-}" == *"multicast"* ]]; then
    TOFINO_STAGES=18
else
    TOFINO_STAGES=15
fi

# These describe which version of the SDE to download and where to find it
SDE_COMMIT=e61fe02c3c1c384b2e212c90177fcea76a31fd4e
SDE_PKG_SHA256=8a87a9b0bed3c5440a173a7a41361bdeb5e7a848882da6b4aa48c8fb0043f3bd
SDE_DEB_SHA256=a292e2dd5311647c4852bb41f2532dd1fdf30325b6d04cccb7e85b873e521d5f

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
