#!/bin/bash

# These describe which version of the SDE to download and where to find it
SDE_COMMIT=c59c6d7b9e512a834f15b1847e636426aec7d670
SDE_PKG_SHA256=c1f024daa62b0f16466c0156fe92e7c5e4ef2ad62db5266507410dbd5a4fb951
SDE_DEB_SHA256=7526d1c02064f4e40056b0a8a5aa1db86f0a912035a80fa223c322b1ae2709b7

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
