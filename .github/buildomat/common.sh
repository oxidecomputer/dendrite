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
SDE_COMMIT=56795dcbceeea59903fa460e301c0932d34984da
SDE_PKG_SHA256=5c3ffd0eb0774747332181e7a8941c8055e331d1fc4a1d831d7097611cd3a314
SDE_DEB_SHA256=17eca652e293fdfe69a5de752a3b3c97b3a09c59d7ee1eaf6804ef6b15278d21

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
