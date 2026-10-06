#!/bin/bash
#:
#: name = "macos"
#: variety = "basic"
#: target = "ubuntu-22.04"
#: output_rules = [
#:   "=/work/macos-aarch64/dpd",
#:   "=/work/macos-aarch64/dpd.sha256.txt",
#:   "=/work/macos-aarch64/swadm",
#:   "=/work/macos-aarch64/swadm.sha256.txt",
#: ]
#:
#: [[publish]]
#: series = "macos-aarch64"
#: name = "dpd"
#: from_output = "/work/macos-aarch64/dpd"
#:
#: [[publish]]
#: series = "macos-aarch64"
#: name = "dpd.sha256.txt"
#: from_output = "/work/macos-aarch64/dpd.sha256.txt"
#:
#: [[publish]]
#: series = "macos-aarch64"
#: name = "swadm"
#: from_output = "/work/macos-aarch64/swadm"
#:
#: [[publish]]
#: series = "macos-aarch64"
#: name = "swadm.sha256.txt"
#: from_output = "/work/macos-aarch64/swadm.sha256.txt"

set -o errexit
set -o pipefail
set -o xtrace

function digest {
    shasum -a 256 "$1" | awk -F ' ' '{print $1}'
}

banner "packages"
sudo apt update
sudo apt install -y jq unzip

# Buildomat doesn't have macOS workers. Our workaround is to build in GitHub
# Actions and poll for that over here.
banner "fetch"
# Set a 40 minute timeout since buildomat's GitHub token lasts an hour.
#
# XXX This is definitely not great and it would be much better to only kick off
# the buildomat job once GHA is complete.
timeout 40m .github/buildomat/fetch-gh-artifacts.sh build-macos

banner "unpack"

staging=/work/staging
mkdir -p "${staging}"
unzip macos-aarch64.zip -d "${staging}"
for bin in dpd swadm; do
    digest "${staging}/${bin}" > "${staging}/${bin}.sha256.txt"
done
mv "${staging}" /work/macos-aarch64
