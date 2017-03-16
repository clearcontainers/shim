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

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -std=gnu99 -fstack-protector -Wall -pedantic \
	-Wstrict-prototypes -Wundef -fno-common \
	-Werror-implicit-function-declaration \
	-Wformat -Wformat-security -Werror=format-security \
	-Wconversion -Wunreachable-code

libexec_PROGRAMS = cc-shim

cc_shim_CFLAGS = \
	$(AM_CFLAGS)

cc_shim_SOURCES = \
	src/shim.c \
	src/shim.h \
	src/utils.c \
	src/utils.h \
	src/log.c \
	src/log.h

check : check-shim

check-shim:
	$(AM_V_GEN)shim_test_common_args="-v -timeout 5s  $(srcdir)/tests -shimpath $(abs_builddir)/cc-shim" ; \
	go test -race $$shim_test_common_args || go test $$shim_test_common_args
