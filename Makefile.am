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

# Has a value if building in a git tree
GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null)

TARGET = cc-shim

# Has a value if building in a git-archive(1)-generated tree
# (see .gitattributes).
GENERATED_COMMIT = $(shell cat commit_id.fmt 2>/dev/null \| grep \'^[a-f0-9][a-f0-9]*\$\')

commit_id:
	$(AM_V_GEN)if [ "x$(GIT_COMMIT)" != "x" ]; then \
		echo "Determining commit id from git"; \
		echo "$(GIT_COMMIT)" > commit_id; \
	elif [ "x$(GENERATED_COMMIT)" != "x" ]; then \
		echo "Determining commit id from generated value"; \
		echo "$(GENERATED_COMMIT)" > commit_id; \
	else \
		echo "WARNING: cannot determine actual commit id"; \
		echo "0" > commit_id; \
	fi

STORED_COMMIT = $(shell cat $(builddir)/commit_id 2>/dev/null || cat $(srcdir)/commit_id 2>/dev/null)

AM_CFLAGS = -std=gnu99 -fstack-protector -Wall -pedantic \
	-Wstrict-prototypes -Wundef -fno-common \
	-Werror-implicit-function-declaration \
	-Wformat -Wformat-security -Werror=format-security \
	-Wconversion -Wunreachable-code \
	-fPIE -O2

AM_LDFLAGS = -pie -z noexecstack -z relro -z now

AM_CPPFLAGS = -D_FORTIFY_SOURCE=2 \
		-DGIT_COMMIT=\"$(STORED_COMMIT)\"

libexec_PROGRAMS = $(TARGET)

cc_shim_CFLAGS = \
	-DSHIM_NAME="\"$(TARGET)\"" \
	$(AM_CFLAGS)

cc_shim_SOURCES = \
	src/shim.c \
	src/shim.h \
	src/utils.c \
	src/utils.h \
	src/log.c \
	src/log.h

src/cc_shim-shim.$(OBJEXT): \
         commit_id

clean-local:
	rm -f commit_id

check : $(CHECK_DEPS)

CHECK_DEPS = check-shim

check-shim:
	$(AM_V_GEN)shim_test_common_args="-v -timeout 5s  $(srcdir)/tests -shimpath $(abs_builddir)/cc-shim" ; \
	go test -race $$shim_test_common_args || go test $$shim_test_common_args

if CPPCHECK
CHECK_DEPS += cppcheck
cppcheck:
	@$(CPPCHECK_PATH) --enable=performance,unusedFunction,missingInclude \
		--language=c --std=c99 --std=posix \
		--error-exitcode=1 -I$(srcdir)/src $(srcdir)/src
endif

EXTRA_DIST= \
	.ci \
	commit_id \
	vendor \
	CONTRIBUTING.md \
	README.md
