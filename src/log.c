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
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "log.h"
#include "utils.h"

static bool debug;

/*!
 * Setup logging.
 *
 * \param _debug Bool for logging debug output.
 */
void shim_log_init(bool _debug)
{
	int syslog_options = (LOG_PID | LOG_NOWAIT);

	debug = _debug;
	openlog(0, syslog_options, LOG_USER);
}

static const char *
get_log_level(int priority) {
	static const char *level = "unknown";

	switch(priority) {
	case LOG_EMERG:
		level = "emergency";
		break;

	case LOG_ALERT:
		level = "alert";
		break;

	case LOG_CRIT:
		level = "critical";
		break;

	case LOG_ERR:
		level = "error";
		break;

	case LOG_WARNING:
		level = "warning";
		break;

	case LOG_NOTICE:
		level = "notice";
		break;

	case LOG_INFO:
		level = "info";
		break;

	case LOG_DEBUG:
		level = "debug";
	}

	return level;
}

/*!
 * Log to syslog.
 *
 * \param priority Syslog priority.
 * \param func Function at call site.
 * \param line_number Call site line number.
 * \param format Format and arguments to log.
 */
void shim_log(int priority, const char *func, int line_number, const char *format, ...)
{
	va_list vargs;
	char *buf;
	size_t len;
	char time_buffer[SHIM_TIME_BUFFER_SIZE];
	char *quoted = NULL;

	if (! (format && func)) {
		return;
	}

	if (priority < LOG_EMERG || priority > LOG_DEBUG) {
		return;
	}

	if (priority == LOG_DEBUG && !debug) {
		return;
	}

	va_start(vargs, format);
	if (vasprintf(&buf, format, vargs) == -1) {
		va_end(vargs);
		return;
	}

	va_end(vargs);

	if (priority <=  LOG_ERR) {
		fprintf(stderr, "%s:%d:%s\n", func, line_number, buf);
	}

	len = strlen(buf);
	if (len >= 2 && buf[len-1] == '\n') {
		/* remove newline */
		buf[len-1] = '\0';
	}

	if (get_time_iso8601 (time_buffer, sizeof(time_buffer)) < 0) {
		time_buffer[0] = '\0';
	}

	quoted = quote_string(buf);
	if (! quoted) {
		return;
	}

	syslog(priority, "time=\"%s\" level=\"%s\" pid=%d function=\"%s\" line=%d source=\"%s\" name=\"%s\" msg=\"%s\"",
			time_buffer,
			get_log_level(priority),
			getpid(),
			func,
			line_number,
			"shim",
			SHIM_NAME,
			quoted);

	free(buf);
	free(quoted);
}
