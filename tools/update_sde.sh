#!/bin/bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/
#
# Copyright 2025 Oxide Computer Company

set -o pipefail
set -o errexit

SOURCE_DIR="$( git rev-parse --show-toplevel )"
CONFIG_FILE=$SOURCE_DIR/.github/buildomat/common.sh

function usage {
    echo "usage: $0 [-c COMMIT] [-n]"
    echo
    echo "  -b COMMIT   Ask to update tofino-sde to HEAD on the named branch."
    echo "  -c COMMIT   Ask to update tofino-sde to a specific commit."
    echo "              If this is unset, Github is queried."
    echo "  -n          Dry-run"
    exit 1
}

REPO="oxidecomputer/tofino-sde"

bad_target_commit() {
    echo "ERROR: The target commit does not appear to correspond with a known package"
    exit 1
}

# Get the SHA for a Buildomat artifact.
#
# Note the "series" component of the Buildomat public file hierarchy
# is the optional 4th argument, and defaults to "image".
function get_sha {
    REPO="$1"
    COMMIT="$2"
    ARTIFACT="$3"
    SERIES="${4:-image}"
    curl -fsS "https://buildomat.eng.oxide.computer/public/file/$REPO/$SERIES/$COMMIT/$ARTIFACT.sha256.txt"
}

function get_latest_commit_from_gh {
    REPO="$1"
    if [[ -z "$2" ]]; then
	    TARGET_BRANCH=oxide
    else
	    TARGET_BRANCH="$2"
    fi

    curl -fsS "https://buildomat.eng.oxide.computer/public/branch/$REPO/$TARGET_BRANCH"
}

function main {
    TARGET_COMMIT=""
    DRY_RUN=""
    while getopts "b:c:n" o; do
      case "${o}" in
        b)
          TARGET_BRANCH="$OPTARG"
          ;;
        c)
          TARGET_COMMIT="$OPTARG"
          ;;
        n)
          DRY_RUN="yes"
          ;;
        *)
          usage
          ;;
      esac
    done

    if [[ -z "$TARGET_COMMIT" ]]; then
        TARGET_COMMIT=$(get_latest_commit_from_gh "$REPO" "$TARGET_BRANCH")
    fi
    PKG_TARGET_SHA=$(get_sha "$REPO" "$TARGET_COMMIT" tofino_sde.p5p illumos) || bad_target_commit
    DEB_TARGET_SHA=$(get_sha "$REPO" "$TARGET_COMMIT" tofino_sde.deb linux) || bad_target_commit

    IN_PLACE="-i"
    if [[ "$DRY_RUN" == "yes" ]]; then
      IN_PLACE="-n"
    fi
    sed $IN_PLACE -e "s/SDE_COMMIT=.*/SDE_COMMIT=$TARGET_COMMIT/g" "$CONFIG_FILE"
    sed $IN_PLACE -e "s/SDE_PKG_SHA256=.*/SDE_PKG_SHA256=${PKG_TARGET_SHA}/g" "$CONFIG_FILE"
    sed $IN_PLACE -e "s/SDE_DEB_SHA256=.*/SDE_DEB_SHA256=${DEB_TARGET_SHA}/g" "$CONFIG_FILE"
    echo "OK: Update complete"
}

main "$@"
