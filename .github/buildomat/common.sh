#!/bin/bash

# These describe which version of the SDE to download and where to find it
SDE_COMMIT=eb08b0b0e55792bbba206202603da0fd791ea555
SDE_PKG_SHA256=fbaea9ccd7ece70cdc20207e2f9b4750243468c6fe95c6a1fae9734201307db7
SDE_DEB_SHA256=14050fd9a08b8b0b2ec7c827fa06a51516369a81bcf616d16699302b58d8ea9a

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
