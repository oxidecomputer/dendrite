#!/bin/bash
#:
#: name = "dpd_openapi"
#: variety = "basic"
#: target = "helios-2.0"
#: output_rules = [
#:   "/out/*",
#: ]
#:
#: [[publish]]
#: series = "openapi"
#: name = "dpd.json"
#: from_output = "/out/dpd.json"
#:
#: [[publish]]
#: series = "openapi"
#: name = "dpd.json.sha256.txt"
#: from_output = "/out/dpd.json.sha256.txt"

set -o errexit
set -o pipefail
set -o xtrace

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
cp openapi/dpd.json /out/dpd.json
digest -a sha256 /out/dpd.json > /out/dpd.json.sha256.txt
