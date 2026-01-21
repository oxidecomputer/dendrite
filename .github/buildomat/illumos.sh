# Download the SDE from CI, verify its integrity, and install it
banner "sde setup"


export SDE=/opt/oxide/tofino_sde
export LD_LIBRARY_PATH="$SDE/lib:$LD_LIBRARY_PATH"

# Install a couple of non-standard packages needed to build dendrite
banner "packages"

cargo --version
rustc --version
