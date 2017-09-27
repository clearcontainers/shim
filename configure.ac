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

AC_PREREQ([2.69])
AC_INIT([shim], [3.0.1])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror -Wno-portability silent-rules subdir-objects color-tests no-dist-gzip dist-xz])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([src/shim.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_LANG(C)

LT_INIT

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MKDIR_P

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h fcntl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([atexit dup2 memset strdup])

AC_CHECK_PROG(GO,[go],[yes],[no])

AC_ARG_ENABLE(cppcheck, AS_HELP_STRING([--enable-cppcheck], [enable static analysis @<:@default=no@:>@]),
          [], [enable_cppcheck=no])
AS_IF([test x"$enable_cppcheck" = "xyes"],
    [AC_SUBST([CPPCHECK], [1])],
    [AC_SUBST([CPPCHECK], [0])])
AM_CONDITIONAL([CPPCHECK], [test x$enable_cppcheck = x"yes"])

AS_IF([test $CPPCHECK = 1],
   [AC_PATH_PROG([CPPCHECK_PATH], [cppcheck], [no], [$PATH:/sbin:/usr/sbin])
   if test x"$CPPCHECK_PATH" == x"no" ; then
       AC_MSG_ERROR([Please install cppcheck.])
   fi
   AC_SUBST(CPPCHECK_PATH)]
)

AC_OUTPUT
