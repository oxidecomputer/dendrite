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
SDE_COMMIT=0af3643d410b7d06fce709b066287ce14e2e5b3d
SDE_PKG_SHA256=5060910618848a8f6c93fb5ecf3b9a46b2d4d6b1ee6c0db5339e5732d1adfd4d
SDE_DEB_SHA256=17a5bdc0e3ecda6f6c525b338a63f25e171cfa6c0aee745b8115de87832209aa

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
