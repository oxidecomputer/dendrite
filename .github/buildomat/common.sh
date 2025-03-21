#!/bin/bash

# These describe which version of the SDE to download and where to find it
SDE_COMMIT=0e4cfe10c92db223a953923d77f09a299b82157b
SDE_PKG_SHA256=89795e536cfc9713a892904480c6c1d7bff99ca8b9e16ba8c3955fb548e037fe
SDE_DEB_SHA256=deb3015f8f8a46a16de8d7ddfa549d353a658105a0dcb963e5bd65587f3d0758

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
