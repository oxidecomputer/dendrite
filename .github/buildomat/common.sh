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
SDE_COMMIT=6c2d4c50abc4a30b119e0131c44b98b1fa3e0b6e
SDE_PKG_SHA256=12f4f30e0ec6bfa1ffa2014de12ff899f99673d25f61598b13b08434e3cad690
SDE_DEB_SHA256=d46dd85d9e3aa7bbdc045f613ab93cba0bc851c29c52be7eeff61583fe02bffa

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
