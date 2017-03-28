#!/bin/bash
# Copyright (c) 2016 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e -x

source $(dirname "$0")/go-env.sh

#
# Install go
#
go_version=1.7

go_tarball="go${go_version}.linux-amd64.tar.gz"
curl -L -O "https://storage.googleapis.com/golang/$go_tarball"
tar xvf $go_tarball 1>/dev/null
mv go $GOROOT
go version

# Unfortunately, go doesn't support vendoring outside of GOPATH (maybe in 1.8?)
# So, we setup a GOPATH tree with our vendored dependencies.
# See: https://github.com/golang/go/issues/14566
mkdir -p "$GOPATH/src"
cp -r vendor/* "$GOPATH/src"

# We also need to put the shim into its right place in the GOPATH so we can
# self-import internal packages
mkdir -p "$GOPATH/src/github.com/clearcontainers/"
ln -s "$PWD" "$GOPATH/src/github.com/clearcontainers/"

#
# Install packages
#
pkgs="cppcheck"

sudo apt-get -qq update
eval sudo apt-get -qq install "$pkgs"
