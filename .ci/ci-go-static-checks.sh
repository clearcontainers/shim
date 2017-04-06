#!/bin/bash
# Copyright (c) 2017 Intel Corporation
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

go get github.com/fzipp/gocyclo
go get github.com/client9/misspell/cmd/misspell
go get github.com/golang/lint/golint
go get github.com/gordonklaus/ineffassign

go_packages=$(go list ./... | grep -v "shim/vendor" | sed -e 's@.*/shim/@./@')
go_files=`go list -f  '{{.Dir}}/*.go' $go_packages`

echo "Running misspell..."
go list -f '{{.Dir}}/*.go' $go_packages |\
    xargs -I % bash -c "misspell -error %"

echo "Running golint..."
for p in $go_packages; do golint -set_exit_status $p; done

echo "Running cyclo..."
gocyclo -over 15 $go_files

echo "Running go vet..."
go vet $go_packages

echo "Running gofmt..."
gofmt -s -d -l $go_files | tee /dev/tty | \
    wc -l | xargs -I % bash -c "test % -eq 0"

echo "Running ineffassign..."
go list -f '{{.Dir}}' $go_packages | xargs -L 1 ineffassign

echo "All go static checks have passed"
