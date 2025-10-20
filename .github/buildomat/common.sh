#!/bin/bash

# These describe which version of the SDE to download and where to find it
SDE_COMMIT=ca9e534e9e7e0f2f87c79f149fa17dba2df76e00
SDE_PKG_SHA256=0c1cc868343d6c64e32522d02374707dee7ad09eab513aa110a320ba0c8c1799
SDE_DEB_SHA256=ca8fe4026d5a5661d860799a3772bcac7a2158fe0a55f269d38e81f0c230aaf3

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
