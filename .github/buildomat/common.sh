#!/bin/bash

# The tofino2 has 20 stages, and the current sidecar.p4 needs all 20 of them.
# Specifying the number of stages isn't strictly necessary, but it allows us to
# track when we exceed the current ceiling. The underlying intention is to grow
# deliberately and thoughtfully, given the limited space on the ASIC.
#
# Note: this now seems silly since we have maxed out the number of stages, but
# we want to leave this check and note in place should we ever find a way to
# reduce our footprint below 20 stages.
TOFINO_STAGES=20

# These describe which version of the SDE to download and where to find it
SDE_COMMIT=9e7c6013287a8ded2a5849bd3b50984e78d81615
SDE_PKG_SHA256=ddabee6ba9440814fbdcf67515089c357ab5b5569a8c51bef8ca7ff48a0983b3
SDE_DEB_SHA256=75ae68b212f50f6320a49c8b794f56c0408b738b1fb4794eb607ef06240098b9

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
