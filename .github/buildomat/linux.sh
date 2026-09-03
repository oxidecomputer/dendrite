# shellcheck shell=bash

function digest {
    local out
    out=$(shasum -a 256 "$1")
    echo "${out%% *}"
}

# Download the SDE from CI, verify its integrity, and install it
banner "sde setup"

export PKG=tofino_sde.deb

# shellcheck disable=SC2154 # SDE_DIR comes from common.sh
curl -OL "${SDE_DIR}/${PKG}"
SDE_CALC=$(digest "${PKG}")

# shellcheck disable=SC2154 # SDE_DEB_SHA256 comes from common.sh
if [[ "${SDE_CALC}" != "${SDE_DEB_SHA256}" ]]; then
	echo "downloaded tofino_sde has a bad checksum"
	exit 1
fi
sudo dpkg -i "${PKG}"

export SDE=/opt/oxide/tofino_sde
export LD_LIBRARY_PATH="${SDE}/lib:${LD_LIBRARY_PATH}"

cargo --version
rustc --version
