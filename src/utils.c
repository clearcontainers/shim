// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <regex.h>

#include "log.h"
#include "utils.h"

/* Signals that should be forwarded by the shim.
 * Commented out signals are handled by the default signal handler
 * as it is appropriate for those signals to be handled by the default handler.
 */
int shim_signal_table[] = {
	SIGHUP,              /* Hangup */
	SIGINT,              /* Interrupt */
	//SIGQUIT,           /* Quit */
	//SIGILL,            /* Illegal instruction */
	SIGTRAP,             /* Trace Trap */
	//SIGABRT,           /* Abort */
	SIGIOT,              /* IOT trap  */
	//SIGBUS,            /* BUS error */
	//SIGFPE,            /* Floating-point exception  */
	//SIGKILL,           /* Kill, unblockable */
	SIGUSR1,             /* User-defined signal 1  */
	//SIGSEGV,           /* Segmentation violation  */
	SIGUSR2,             /* User-defined signal 2  */
	//SIGPIPE,           /* Broken pipe */
	SIGALRM,             /* Alarm clock */
	SIGTERM,             /* Termination */
	SIGSTKFLT,           /* Stack fault  */
	SIGCLD,              /* Same as SIGCHLD */
	SIGCHLD,             /* Child status has changed */
	SIGCONT,             /* Continue */
	//SIGSTOP,           /* Stop, unblockable */
	SIGTSTP,             /* Keyboard stop */
	SIGTTIN,             /* Background read from tty */
	SIGTTOU,             /* Background write to tty */
	SIGURG,              /* Urgent condition on socket */
	SIGXCPU,             /* CPU limit exceeded */
	SIGXFSZ,             /* File size limit exceeded */
	SIGVTALRM,           /* Virtual alarm clock */
	SIGPROF,             /* Profiling alarm clock */
	SIGWINCH,            /* Window size change */
	SIGPOLL,             /* Pollable event occurred */
	SIGIO,               /* I/O now possible */
	SIGPWR,              /* Power failure restart */
	//SIGSYS,            /* Bad system call */
	SIGUNUSED,
	0,
};

/*!
 * Set file descriptor as non-blocking
 *
 * \param fd File descriptor to set as non-blocking
 *
 * \return true on success, false otherwise
 */
bool
set_fd_nonblocking(int fd)
{
	int flags;

	if (fd < 0) {
		return false;
	}

	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		shim_error("Error getting status flags for fd: %s\n", strerror(errno));
		return false;
	}
	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1) {
		shim_error("Error setting fd as nonblocking: %s\n", strerror(errno));
		return false;
	}
	return true;
}

/*
 * Verify string is in base64url encoding format
 *
 *\param s string to verify
 *
 *\return 0 on success, -1 on failure
 */
int
verify_base64url_format(char *s)
{
	regex_t pattern;
	int ret = -1;
	char *regex = NULL;
	char errbuf[256];

	/* Alphabet set for base64 url encoding.
	 * See : https://tools.ietf.org/html/rfc4648#page-8
	 */
	const char *alph_set = "[a-zA-Z0-9_\\-]";

	if (!s)	{
		return -1;
	}

	/* base64 encoded string consists of 4 letter blocks from base64
	 * alphabet set, and may end with a 3 letter block followed by "=" for
	 * padding or a 2 letter block followed by "==" for padding.
	 *
	 * See: https://tools.ietf.org/html/rfc4648#section-4
	 */
	ret = asprintf(&regex, "^(%1$s{4})*(%1$s{4}|%1$s{3}=|%1$s{2}==)$",
				alph_set);

	if ( !regex) {
		abort();
	}

	ret = regcomp(&pattern, regex, REG_EXTENDED);
	if ( ret == -1) {
		shim_error("Could not compile base64url encoding regular"
			"expression: %s\n", strerror(errno));
		goto out;
	}

	ret = regexec(&pattern, s, 0, NULL, 0);
	if (ret != 0) {
		regerror(ret, &pattern, errbuf, sizeof(errbuf));
		shim_error("Could not verify string for base64url "
			"encoding: %s\n", errbuf);
		ret = -1;
	}

out:
	free(regex);
	regfree(&pattern);
	return ret;
}

/*!
 * Store short integer as big endian in buffer
 *
 * \param buf Buffer to store the value in
 * \param val Short Integer to be converted to big endian
 */
void
set_big_endian_16(uint8_t *buf, uint16_t val)
{
	if (! buf) {
		return;
	}
	buf[0] = (uint8_t)(val >> 8);
	buf[1] = (uint8_t)val;
}

/*!
 * Convert the value stored in buffer to little endian
 *
 * \param buf Buffer storing the big endian value
 *
 * \return Unsigned 16 bit network ordered integer
 */
uint16_t
get_big_endian_16(const uint8_t *buf)
{
	if (! buf) {
		return 0;
	}
	return (uint16_t)(buf[0] << 8 | buf[1] );
}

/*!
 * Store integer as big endian in buffer
 *
 * \param buf Buffer to store the value in
 * \param val Integer to be converted to big endian
 */
void
set_big_endian_32(uint8_t *buf, uint32_t val)
{
        buf[0] = (uint8_t)(val >> 24);
        buf[1] = (uint8_t)(val >> 16);
        buf[2] = (uint8_t)(val >> 8);
        buf[3] = (uint8_t)val;
}

/*!
 * Convert the value stored in buffer to little endian
 *
 * \param buf Buffer storing the big endian value
 *
 * \return Unsigned 32 bit network ordered integer
 */
uint32_t
get_big_endian_32(const uint8_t *buf)
{
        return (uint32_t)(buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]);
}

/*!
 * Store 64 bit value in network byte order in buffer
 *
 * \param buf Buffer to store the value in
 * \param val 64 bit value to be converted to big endian
 */
void
set_big_endian_64(uint8_t *buf, uint64_t val)
{
	set_big_endian_32(buf, (uint32_t)(val >> 32));
	set_big_endian_32(buf + 4, (uint32_t)val);
}

/*!
 * Convert 64 bit value stored in buffer to little endian
 *
 * \param buf Buffer storing the big endian value
 *
 * \return Unsigned 64 bit network ordered integer
 */
uint64_t
get_big_endian_64(const uint8_t *buf)
{
	uint64_t val;

	val = ((uint64_t)get_big_endian_32(buf) << 32) | get_big_endian_32(buf+4);
	return val;
}
