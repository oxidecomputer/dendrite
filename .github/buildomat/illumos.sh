# Download the SDE from CI, verify its integrity, and install it
banner "sde setup"

export PKG=tofino_sde.p5p
curl -OL $SDE_DIR/$PKG
SDE_CALC=`digest -a sha256 $PKG`
if [ $SDE_CALC != $SDE_PKG_SHA256 ]; then
	echo "downloaded tofino_sde has a bad checksum"
	exit 1
fi
pfexec pkg install -g $PKG tofino_sde

export SDE=/opt/oxide/tofino_sde
export LD_LIBRARY_PATH="$SDE/lib:$LD_LIBRARY_PATH"

# Install a couple of non-standard packages needed to build dendrite
banner "packages"
pfexec pkg install clang-15 pcap
pfexec pkg set-mediator -V 15 clang llvm

cargo --version
rustc --version
