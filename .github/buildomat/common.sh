#!/bin/bash

# The tofino2 has 20 stages. The base sidecar.p4 builds at 16 stages, and,
# with multicast enabled, at 19. Specifying the number of stages isn't
# strictly necessary, but it allows us to track when we exceed the current
# ceiling. The underlying intention is to grow deliberately and thoughtfully,
# given the limited space on the ASIC.
#
# Note: p4c does multiple placement rounds. table_summary.log reports each
# round. The first (unconstrained) is informational, and the final (at the
# bottom of the log) is what the binary actually uses. If
# --num-stages-override cannot be satisfied, the assembler errors out and
# no binary is produced.
TOFINO_STAGES=16

# These describe which version of the SDE to download and where to find it
SDE_COMMIT=2a6b33211c9675996dcb99fe939045506667ae94
SDE_PKG_SHA256=d32739c368d1666b98dd74e25e22f83c209982e2c6670de6db5d6fdf49b5e275
SDE_DEB_SHA256=3ecbf7c677bb722b351d5af74cee44fab70c1bb5eadc6ab2558ba714a8c3978b

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
