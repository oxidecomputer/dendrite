#!/bin/bash
#:
#: name = "shellcheck"
#: variety = "basic"
#: target = "ubuntu-24.04"

banner "packages"
sudo apt update
sudo apt install -y shellcheck=0.9.0-*

banner "shellcheck"

shopt -s globstar
shellcheck -x -o all .github/buildomat/**/*.sh
