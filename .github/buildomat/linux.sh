function digest {
    shasum -a 256 "$1" | awk -F ' ' '{print $1}'
}

# Download the SDE from CI, verify its integrity, and install it
banner "sde setup"

export PKG=tofino_sde.deb
curl -OL $SDE_DIR/$PKG
SDE_CALC=`digest $PKG`
if [ $SDE_CALC != $SDE_DEB_SHA256 ]; then
	echo "downloaded tofino_sde has a bad checksum"
	exit 1
fi
pfexec dpkg -i $PKG

export SDE=/opt/oxide/tofino_sde
export LD_LIBRARY_PATH="$SDE/lib:$LD_LIBRARY_PATH"

cargo --version
rustc --version
