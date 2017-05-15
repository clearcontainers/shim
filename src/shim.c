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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/un.h>
#include <poll.h>
#include <assert.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdbool.h>
#include <limits.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

#include "utils.h"
#include "log.h"
#include "shim.h"

/* globals */

struct pollfd poll_fds[MAX_POLL_FDS] = {{-1}};

// File descriptors are added at specific index in the poll_fds array
#define SIGNAL_FD_INDEX 0
#define PROXY_SOCK_INDEX 1
#define STDIN_INDEX 2

/* Pipe used for capturing signal occurence */
int signal_pipe_fd[2] = { -1, -1 };

static char *program_name;

struct termios *saved_term_settings;

/*!
 * Add file descriptor to the array of polled descriptors
 *
 * \param poll_fds Array of polled fds
 * \param index Index at which the fd is added
 * \param fd File descriptor to add
 * \param events Events for the fd that should be polled
 */
void add_pollfd(struct pollfd *poll_fds, nfds_t index, int fd,  short events) {
	struct pollfd pfd = { 0 };

	if ( !poll_fds || fd < 0 || index >= MAX_POLL_FDS) {
		shim_warning("Not able to add fd to poll_fds array\n");
		return;
	}

	pfd.fd = fd;
	pfd.events = events;
	poll_fds[index] = pfd;
}

/*!
 * Signal handler for the signals that should be caught and 
 * forwarded to the proxy
 *
 * \param signal_no Signal number of the signal caught
 */
static void
signal_handler(int signal_no)
{
	int savedErrno;                     /* In case we change 'errno' */
 
	savedErrno = errno;
	/* Write signal number to pipe, so that the signal can be identfied later */
	if (write(signal_pipe_fd[1], &signal_no, sizeof(signal_no)) == -1 && errno != EAGAIN) {
		return;
	}
	errno = savedErrno;
}

/*!
 * Assign signal handler for all the signals that should be
 * forwarded by the shim to the proxy.
 *
 * \param sa Signal handler
 * \return true on success, false otherwise
 */
bool
assign_all_signals(struct sigaction *sa)
{
	if (! sa) {
		return false;
	}

        for (int i = 0; shim_signal_table[i]; i++) {
                if (sigaction(shim_signal_table[i], sa, NULL) == -1) {
			shim_error("Error assigning signal handler for %d : %s\n",
				shim_signal_table[i], strerror(errno));
                        return false;
                }
        }
        return true;
}

void restore_terminal(void) {
	if ( isatty(STDIN_FILENO) && saved_term_settings) {
		if (tcsetattr (STDIN_FILENO, TCSANOW, saved_term_settings)) {
			shim_warning("Unable to restore terminal: %s\n",
					strerror(errno));
		}
		free(saved_term_settings);
		saved_term_settings = NULL;
	}
}

/*!
 * Print formatted message to stderr and exit with EXIT_FAILURE
 *
 * \param format Format that specifies how subsequent arguments are
 *  converted for output
 */
void
err_exit(const char *format, ...)
{
	va_list	args;

	if ( !format) {
		return;
	}
	fprintf(stderr, "%s: ", program_name);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	restore_terminal();
	exit(EXIT_FAILURE);
}

/*
 * Prepare byte stream in the proxy protocol format.
 *
 * \param fr \ref frame
 * \param [out] total_size Total size of serialized byte stream
 */
uint8_t*
serialize_frame(struct frame *fr, ssize_t *total_size)
{
	uint8_t *msg = NULL;

	if (! (fr && total_size)) {
		return NULL;
	}

	/* Header length is length of the header in number of 32 bit words.
	 * Converting the header length to byte length.
	 */
	*total_size = (ssize_t)((fr->header.header_len * sizeof(uint32_t)) + fr->header.payload_len);

	msg = calloc((size_t)(*total_size), sizeof(uint8_t));

	if (! msg) {
		abort();
	}

	set_big_endian_16(msg, PROXY_VERSION);
	msg[HEADER_LEN_OFFSET] = fr->header.header_len;
	msg[RES_OFFSET] =  fr->header.type;
	msg[OPCODE_OFFSET] =  fr->header.opcode;
	set_big_endian_32(msg + PAYLOAD_LEN_OFFSET, fr->header.payload_len);

	if (fr->header.payload_len && fr->payload) {
		strncpy((char *)msg + PAYLOAD_OFFSET, (const char*)fr->payload,
				fr->header.payload_len);
	}

	return msg;
}

/*!
 * Write frame to the proxy socket fd.
 *
 * \param shim \ref cc_shim
 * \param fr \ref frame
 *
 * \return true on success, false otherwise
 */
bool
write_frame(struct cc_shim *shim, struct frame *fr)
{
	size_t     offset = 0;
	ssize_t    ret;
	ssize_t    total_size = 0;

	if (! (shim && fr)) {
		return false;
	}

	uint8_t *msg = serialize_frame(fr, &total_size);

	if (! msg ) {
		return false;
	}

	while (offset < total_size) {
		ret = write(shim->proxy_sock_fd, msg + offset, (size_t)total_size-offset);
		if (ret == -1 && errno == EINTR) {
			continue;
		}
		if (ret <= 0 ) {
			free(msg);
			shim_error("Error writing to proxy: %s\n", strerror(errno));
			return false;
		}
		offset += (size_t)ret;
	}
	free(msg);
	return true;
}

/*!
 * Send message to proxy.
 *
 * \param shim \ref cc_shim
 * \param type Type of message
 * \param opcode Opcode of message type
 * \param payload Payload to be sent
 * 
 * \return true on success, false otherwise
 */
bool
send_proxy_message(struct cc_shim *shim, uint8_t type, uint8_t opcode,
			const char *payload)
{
	struct frame fr = {{ 0 }};
	bool ret;

	if ( !shim || shim->proxy_sock_fd < 0) {
		return false;
	}

	fr.header.version = PROXY_VERSION;
	fr.header.header_len = MIN_HEADER_WORD_SIZE;
	fr.header.type = type;
	fr.header.opcode = opcode;

	shim_debug("Sending frame of type:%d, opcode:%d, payload:%s\n",
			fr.header.type,
			fr.header.opcode,
			payload? payload:"(empty)");

	if (payload) {
		fr.header.payload_len = (uint32_t)strlen(payload);
		fr.payload = (uint8_t*)payload;
	}

	ret = write_frame(shim, &fr);
	return ret;
}

/*!
 * Send Connect command to proxy.
 *
 * \param shim \ref cc_shim
 *
 * \return true on success, false otherwise
 */
bool
send_connect_command(struct cc_shim *shim)
{
	char *payload = NULL;
	bool ret;

	if (! shim) {
		return false;
	}

	if ((! shim->token) || (shim->proxy_sock_fd < 0)) {
		return false;
	}

	if ( verify_base64url_format(shim->token) != 0) {
		shim_error("Invalid token: %s, base64 encoded token expected\n",
				shim->token);
		return false;
	}

	// TODO: Verify the payload format
	ret = asprintf(&payload,
			"{\"token\":\"%s\"}", shim->token);

	if (! payload) {
		abort();
	}

	ret = send_proxy_message(shim, frametype_command, cmd_connectshim, payload);
	if (! ret) {
		shim_error("Could not send initial connect command to "
				"proxy at %s\n", shim->proxy_address);
	}

	free(payload);
	return ret;
}

/*!
 * Read message received from proxy.
 *
 * \param fd File descriptor to read the data from.
 * \param buf Buffer to store the data in.
 * \param size Size in bytes to be read.
 *
 * \return true on success, false otherwise
 */
bool read_wire_data(int fd, uint8_t *buf, ssize_t size)
{
	ssize_t ret;
	ssize_t offset = 0;

	if ( fd < 0 || ! buf ) {
		return false;
	}

	do {
		ret = recv(fd, buf, (size_t)(size-offset), 0);
		if (ret == 0) {
			shim_error("Received EOF on file descriptor\n");
			// TODO: Exit for now, add logic to try to reconnect
			// to proxy.
			exit(EXIT_FAILURE);
		} else if (ret < 0) {
			shim_error("Failed to read from fd: %s\n",
				strerror(errno));
			return false;
		}
		if (ret >= size) {
			break;
		}
		offset += ret;
	} while(1);

	return true;
}

/*!
 * Read message received from proxy.
 *
 * \param shim \ref cc_shim
 * \param header \ref frame
 *
 * \return newly allocated frame on success, NULL otherwise
 */
struct frame* 
read_frame(struct cc_shim *shim)
{
	uint8_t *buf = NULL;
	size_t  size = VERSION_SIZE + HEADER_LEN_SIZE;
	size_t header_size_in_bytes;
	struct frame *fr = NULL;

	if ( !shim || shim->proxy_sock_fd < 0) {
		return false;
	}

	buf  = calloc(size, sizeof(uint8_t));
	if ( !buf) {
		abort();
	}

	fr = calloc(1, sizeof(struct frame));
	if ( !fr) {
		abort();
	}

	if (! read_wire_data(shim->proxy_sock_fd, buf, (ssize_t)size)) {
		goto error;
	}

	fr->header.header_len = buf[HEADER_LEN_OFFSET];
	fr->header.version = get_big_endian_16(buf);

	if (fr->header.version != PROXY_VERSION) {
		shim_error("Bad frame version: %d, Expected : %d\n", 
				fr->header.version,
				PROXY_VERSION);
		goto error;
	}

	/* Get the header size in bytes, as the proxy passes the header length
	 * as 32 bit word length.
	 */
	header_size_in_bytes = (size_t)fr->header.header_len * sizeof(uint32_t);

	buf = realloc(buf, header_size_in_bytes);
	if (! buf) {
		abort();
	}

	if (! read_wire_data(shim->proxy_sock_fd, buf + size,
			(ssize_t)(header_size_in_bytes) - (ssize_t)size)) {
		shim_error("Error while reading frame from proxy at %s\n",
				shim->proxy_address);
		goto error;
	}

	fr->header.payload_len = get_big_endian_32(buf + PAYLOAD_LEN_OFFSET);
	fr->header.type = buf[RES_OFFSET] & 0x0F;
	fr->header.err = buf[RES_OFFSET] & 0x10 ;
	fr->header.opcode = buf[OPCODE_OFFSET];

	if (fr->header.payload_len) {
		buf = realloc(buf, fr->header.payload_len + 1);
		if (! buf) {
			abort();
		}

		memset(buf, 0, fr->header.payload_len + 1);
		if (! read_wire_data(shim->proxy_sock_fd, buf, 
				fr->header.payload_len)) {
			goto error;
		}
		fr->payload = buf;
	} else {
		free(buf);
	}

	shim_debug("Frame read - HeaderLength: %d, Version: %d, "
			"Payloadlen: %d, Type:%d, "
			"Opcode: %d, Err:%d\n",
			fr->header.header_len, fr->header.version,
			fr->header.payload_len, fr->header.type,
			fr->header.opcode, fr->header.err);

	return fr;

error:
	free(buf);
	free(fr);
	return NULL;
}

/*!
 * Read signals received and send message in the hyperstart protocol
 * format to the proxy ctl socket.
 *
 * \param shim \ref cc_shim
 */
void
handle_signals(struct cc_shim *shim) {
	int                sig;
	int                ret;
	struct winsize     ws;
	char              *payload = NULL;

	if ( !shim  || shim->proxy_sock_fd < 0) {
		return;
	}

	while (read(signal_pipe_fd[0], &sig, sizeof(sig)) != -1) {
		shim_debug("Handling signal : %d on fd %d\n", sig,
				signal_pipe_fd[0]);
		if (sig == SIGWINCH ) {
			if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == -1) {
				shim_warning("Error getting the current"\
					"window size: %s\n",
					strerror(errno));
				continue;
			}
			ret = asprintf(&payload, "{\"signal\": %d,"\
					" \"row\":%d, \"column\":%d}",
					 sig, ws.ws_row, ws.ws_col);

			shim_debug("handled SIGWINCH for container %s "
				"(row=%d, column=%d)\n",
				shim->container_id? shim->container_id: "",
				ws.ws_row, ws.ws_col);

		} else {
			ret = asprintf(&payload, "{\"signal\":%d}",
                                                         sig);
			shim_debug("Killed container %s with signal %d\n", 
				shim->container_id? shim->container_id: "",
				sig);
		}
		if (ret == -1) {
			abort();
		}

		if (! send_proxy_message(shim, frametype_command,
					cmd_signal, payload)) {
			shim_error("Could not send signal command "
					"to proxy %s\n", shim->proxy_address);
		}

		free(payload);
        }
}

/*!
 * Read data from stdin and send it to proxy.
 *
 * \param shim \ref cc_shim
 */
void
handle_stdin(struct cc_shim *shim)
{
	ssize_t        nread;
	char           buf[BUFSIZ] = { 0 };

	if (! shim || shim->proxy_sock_fd < 0) {
		return;
	}

	nread = read(STDIN_FILENO , buf, BUFSIZ);
	if (nread < 0) {
		shim_warning("Error while reading stdin char :%s\n", strerror(errno));
		return;
	} else if (nread == 0) {
		/* EOF received on stdin, send eof to hyperstart and remove stdin fd from
		 * the polled descriptors to prevent further eof events
		 */
		poll_fds[STDIN_INDEX].fd = -1;
	}

	if (! send_proxy_message(shim, frametype_stream, stream_stdin, buf)) {
		shim_error("Could not send stdin stream to proxy at %s\n",
				shim->proxy_address);
	}
}

/*!
 * Handle response received from proxy
 *
 *\param shim \ref cc_shim
 *\param fr \ref frame
 */
void
handle_proxy_response(struct cc_shim *shim, struct frame *fr)
{
	if (! (shim && shim->proxy_address)) {
		return;
	}

	if ( !fr) {
		return;
	}

	// Reponses received from proxy are currently just logged.
	if (fr->header.err) {
		shim_error("Error response received from proxy at %s: %s\n", 
				shim->proxy_address,
				fr->payload ? (char*)fr->payload:"");

		/* If we receive an error with the ConnectShim response,
		 * the proxy could not validate the token.
		 */
		if (fr->header.opcode == cmd_connectshim) {
			err_exit("Shim received an error in response"
				"to ConnectShim command, exiting");
		}
	} else {
		/* TODO: Currently logging response. Do we want to track responses
		 * to requests in future. Maybe useful for restarting connection with proxy
		 * and resending requests that were missed.
		 */
		shim_debug("Response received from proxy at %s: %s\n", 
				shim->proxy_address,
				fr->payload ? (char*)fr->payload:"");
	}
}

/*!
 * Handle stream received from proxy
 *
 *\param shim \ref cc_shim
 *\param fr \ref frame
 */
void
handle_proxy_stream(struct cc_shim *shim, struct frame *fr)
{
	int outfd = -1;
	ssize_t offset = 0;
	size_t ret;

	if (! (shim && shim->proxy_address)) {
		return;
	}

	if ( fr->header.type != frametype_stream) {
		return;
	}

	if (fr->header.opcode == stream_stdout) {
		outfd = STDOUT_FILENO;
	} else if (fr->header.opcode == stream_stderr) {
		outfd = STDERR_FILENO;
	} else {
		shim_warning("Invalid stream with opcode %d received from proxy at %s\n",
				fr->header.opcode, shim->proxy_address);
		return;
	}

	while (offset < fr->header.payload_len) {
		ret = write(outfd, fr->payload + offset,
				 (size_t)(fr->header.payload_len - offset));
		if (ret <= 0 ) {
			shim_error("Could not write stream to fd %d for proxy %s: %s\n",
					outfd, shim->proxy_address, strerror(errno));
			return;
		}
		offset += (ssize_t)ret;
	}
}

/*!
 * Handle notification received from proxy
 *
 *\param shim \ref cc_shim
 *\param fr \ref frame
 */
void
handle_proxy_notification(struct cc_shim *shim, struct frame *fr)
{
	int code = 0;

	if (! (shim && shim->proxy_address)) {
		return;
	}

	if ( ! ( fr && fr->payload)) {
		return;
	}

	if (fr->header.opcode == notification_exitcode) {
		/* Send disconnect command to proxy and exit
		 * with the exit code
		*/
		code = *(fr->payload);

		if (! send_proxy_message(shim, frametype_command,
					cmd_disconnectshim, NULL)) {
			shim_error("Could not send Disconnect shim command "
				"to proxy at %s\n", shim->proxy_address);
		}

		shim_debug("Exit status for container: %d\n", code);
		restore_terminal();
		exit(code);
	} else {
		shim_warning("Unknown notification received from proxy %s: %d\n",
				shim->proxy_address, fr->header.opcode);
	}
}

/*!
 * Handle message received from proxy
 *
 *\param shim \ref cc_shim
 */
void
handle_proxy_message(struct cc_shim *shim)
{
	struct frame *fr;

	fr = read_frame(shim);
	if ( !fr) {
		return;
	}

	shim_debug("Received frame with type: %d, opcode: %d\n",
			fr->header.type,
			fr->header.opcode);

	switch (fr->header.type) {
		case frametype_response:
			handle_proxy_response(shim, fr);
			break;
		case frametype_stream:
			handle_proxy_stream(shim, fr);
			break;
		case frametype_notification:
			handle_proxy_notification(shim, fr);
			break;
		case frametype_command:
			shim_warning("Command received from proxy\n");
			break;
		default:
			shim_warning("Unknown frame with type %d received\n",
				fr->header.type);
	}

	free(fr->payload);
	free(fr);
}

/*
 * Parse number from input
 *
 * \return Long long integer on success, -1 on failure
 */
long long
parse_numeric_option(char *input) {
	char       *endptr;
	long long   num;

	if ( !input) {
		return -1;
	}

	errno = 0;
	num = strtoll(input, &endptr, 10);
	if ( errno || *endptr ) {
		return -1;
	}
	return num;
}

/*
 * Parse proxy connection uri for connection address
 * and port for tcp.
 * Expected schemes are unix: and tcp:
 *
 * \param shim \ref cc_shim
 * \param uri String containing the uri
 *
 * \return true on success, false on failure
 */
bool
parse_connection_uri(struct cc_shim *shim, char *uri)
{
	const char *unix_uri = "unix://";
	const char *tcp_uri = "tcp://";
	size_t      unix_uri_len = strlen(unix_uri);
	size_t      tcp_uri_len = strlen(tcp_uri);
	bool        ret = false;
	ssize_t     addr_len;

	if (! (shim && uri)) {
		return false;
	}

	if (! strncmp(uri, unix_uri, unix_uri_len)) {
		shim->proxy_address = strdup(uri + unix_uri_len);

		if ( !shim->proxy_address) {
			abort();
		}

		if (strlen(shim->proxy_address) >= PATH_MAX ) {
			shim_error("Path provided for the proxy exceeds"
				"maximum allowed length on paths\n");
			goto out;
		}
		ret = true;
	} else if (! strncmp(uri, tcp_uri, tcp_uri_len)) {
		char *port_offset = strstr(uri + tcp_uri_len, ":");

		if ( !port_offset) {
			shim_error("Missing port in uri %s\n", uri);
			goto out;
		}

		shim->proxy_port = (int)parse_numeric_option(port_offset + 1);
		if (shim->proxy_port == -1) {
			shim_error("Could not parse port in uri %s: %s\n",
					uri, strerror(errno));
			goto out;
		}

		addr_len = port_offset - (uri + tcp_uri_len);

		if (addr_len >= _POSIX_HOST_NAME_MAX) {
			shim_error("Address provided for the proxy exceeds"
				"maximum allowed length for hostname\n");
			goto out;
		}

		if (addr_len == 0) {
			shim_error("Missing tcp hostname in uri %s\n", uri);
			goto out;
		}

		shim->proxy_address = calloc(sizeof(char),
						(size_t)addr_len + 1);

		if ( !shim->proxy_address) {
			abort();
		}

		memcpy(shim->proxy_address, uri + tcp_uri_len,
				(size_t)addr_len * sizeof(char));
		ret = true;
	} else {
		shim_error("Invalid uri scheme : %s\n", uri);
	}
out:
	free(uri);
	return ret;
}

/*
 * Establish tcp/unix connection with proxy.
 *
 * \param shim \ref cc_shim
 *
 * \return true on success, false on failure
 */
bool
connect_to_proxy(struct cc_shim *shim)
{
	int   sockfd = -1;
        char *port_str = NULL;
	int   ret;

	if (! shim) {
		return false;
	}

	/* Uninitialised port means the uri provided is a
	 * unix socket connection path
	 */
	if (shim->proxy_port == -1) {
		struct sockaddr_un remote;
		size_t path_size = sizeof(remote.sun_path);

		sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sockfd == -1 ) {
			shim_error("Error while creating socket: %s\n",
					strerror(errno));
			goto out;
		}

		remote.sun_family = AF_UNIX;
		remote.sun_path[path_size-1] = '\0';
		strncpy(remote.sun_path, shim->proxy_address,
				path_size - 2);

		if (connect(sockfd, (struct sockaddr *)&remote,
				sizeof(struct sockaddr_un)) == -1) {
			shim_error("Error while connecting to proxy "
				"with address %s: %s\n", shim->proxy_address,
				 strerror(errno));
			goto out;
		}
	} else {
		struct addrinfo    hints;
		struct addrinfo   *servinfo, *addr;

		/* Connect to proxy on tcp address+port
		 */
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		/* Avoid service lookups as we provide a numeric port number.
		 */
		hints.ai_flags = AI_NUMERICSERV;

		if ( asprintf(&port_str, "%d", shim->proxy_port) == -1) {
			abort();
		}

		if ((ret = getaddrinfo(shim->proxy_address, port_str,
				&hints, &servinfo)) != 0) {
			shim_error("getaddrinfo error for %s:%d  :%s\n",
				shim->proxy_address,
				shim->proxy_port,
				strerror(errno));
			goto out;
		}


		// loop through all the results and connect to the first we can
		for(addr = servinfo; addr != NULL; addr = addr->ai_next) {
			if ((sockfd = socket(addr->ai_family, addr->ai_socktype,
				addr->ai_protocol)) == -1) {
				shim_debug("Error in socket creation for "
					"%s:%d :%s\n",
					shim->proxy_address,
					shim->proxy_port,
					strerror(errno));
				continue;
			}

			if (connect(sockfd, addr->ai_addr, 
						addr->ai_addrlen) == -1) {
				close(sockfd);
				sockfd = -1;
				shim_debug("Error in client connection for "
					"%s:%d : %s\n", shim->proxy_address,
					shim->proxy_port, strerror(errno));
				continue;
			}
			break;
		}

		if (addr == NULL) {
			shim_error("Failed to connect to proxy with address"
				" %s:%d : %s\n", shim->proxy_address,
				shim->proxy_port, strerror(errno));
			freeaddrinfo(servinfo);
			goto out;
		}
		freeaddrinfo(servinfo);
	}

	free(port_str);
	shim->proxy_sock_fd = sockfd;
	return true;
out:
	free(port_str);
	if (sockfd >= 0) {
		close(sockfd);
	}

	return false;
}

/*!
 * Print program usage
 */
void
print_usage(void) {
        printf("%s: Usage\n", program_name);
        printf("  -c,  --container-id   Container id\n");
        printf("  -d,  --debug          Enable debug output\n");
        printf("  -t,  --token          Connection token passed by cc-proxy\n");
        printf("  -u,  --uri            Connection uri. Supported schemes are tcp: and unix:\n");
        printf("  -h,  --help           Display this help message\n");
}

int
main(int argc, char **argv)
{
	struct cc_shim shim = {
		.container_id   =  NULL,
		.proxy_sock_fd  = -1,
		.token          =  NULL,
		.proxy_address  =  NULL,
		.proxy_port     =  -1,
	};
	int                ret;
	struct sigaction   sa;
	int                c;
	bool               debug = false;
	char              *uri = NULL;

	program_name = argv[0];

	struct option prog_opts[] = {
		{"container-id", required_argument, 0, 'c'},
		{"debug", no_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{"token", required_argument, 0, 't'},
		{"uri", required_argument, 0, 'u'},
		{ 0, 0, 0, 0},
	};

	while ((c = getopt_long(argc, argv, "c:dht:u:", prog_opts, NULL))!= -1) {
		switch (c) {
			case 'c':
				shim.container_id = strdup(optarg);
				break;
			case 't':
				shim.token = strdup(optarg);
				break;
			case 'd':
				debug = true;
				break;
			case 'u':
				uri = strdup(optarg);
				if ( !uri) {
					abort();
				}
				break;
			case 'h':
				print_usage();
				exit(EXIT_SUCCESS);
			default:
				print_usage();
				exit(EXIT_FAILURE);
		}
	}

	if ( !shim.token) {
		err_exit("Missing connection token\n");
	}

	if (! uri) {
		err_exit("Missing connection uri\n");
	}

	shim_log_init(debug);

	/* Using self pipe trick to handle signals in the main loop, other strategy
	 * would be to clock signals and use signalfd()/ to handle signals synchronously
	 */
	if (pipe(signal_pipe_fd) == -1) {
		err_exit("Error creating pipe\n");
	}

	// Add read end of pipe to pollfd list and make it non-bocking
	add_pollfd(poll_fds, SIGNAL_FD_INDEX, signal_pipe_fd[0], POLLIN | POLLPRI);
	if (! set_fd_nonblocking(signal_pipe_fd[0])) {
		exit(EXIT_FAILURE);
	}
	if (! set_fd_nonblocking(signal_pipe_fd[1])) {
		exit(EXIT_FAILURE);
	}

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;           /* Restart interrupted reads()s */
	sa.sa_handler = signal_handler;

	// Change the default action of all signals that should be forwarded to proxy
	if (! assign_all_signals(&sa)) {
		err_exit("sigaction");
	}

	if (! parse_connection_uri(&shim, uri)) {
		goto out;
	}

	if (! connect_to_proxy(&shim)) {
		goto out;
	}

	/* Send a Connect command to the proxy and wait for the response
	 */
	shim_debug("Sending initial connect command\n");
	if (! send_connect_command(&shim)) {
		shim_error("Could not send connect command to proxy\n");
		goto out;
	}

	add_pollfd(poll_fds, PROXY_SOCK_INDEX, shim.proxy_sock_fd, POLLIN | POLLPRI);

	/* Add stdin only if it is attached to a terminal.
	 * If we add stdin in the non-interactive case, since stdin is closed by docker
	 * this causes continuous close events to be generated on the poll loop.
	 */
	if (isatty(STDIN_FILENO)) {
		/*
		 * Set raw mode on the slave side of the PTY. The local pty
		 * (ie. the one on the host side) is configured in raw mode to
		 * be a dumb pipe and forward data to the pty on the VM side.
		 */
		struct termios term_settings;

		tcgetattr(STDIN_FILENO, &term_settings);
		saved_term_settings = calloc(1, sizeof(struct termios));
		if ( !saved_term_settings) {
			abort();
		}
		*saved_term_settings = term_settings;
		cfmakeraw(&term_settings);
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_settings);

		add_pollfd(poll_fds, STDIN_INDEX, STDIN_FILENO, POLLIN | POLLPRI);
	} else if (fcntl(STDIN_FILENO, F_GETFD) != -1) {
		set_fd_nonblocking(STDIN_FILENO);
		add_pollfd(poll_fds, STDIN_INDEX, STDIN_FILENO, POLLIN | POLLPRI);
	}

	ret = atexit(restore_terminal);
	if (ret) {
		shim_debug("Could not register function for atexit");
	}

	while (1) {
		ret = poll(poll_fds, MAX_POLL_FDS, -1);
		if (ret == -1 && errno != EINTR) {
			shim_error("Error in poll : %s\n", strerror(errno));
			break;
		}

		/* check if signal was received first */
		if (poll_fds[SIGNAL_FD_INDEX].revents != 0) {
			handle_signals(&shim);
		}

		// check for proxy sockfd
		if (poll_fds[PROXY_SOCK_INDEX].revents != 0) {
			handle_proxy_message(&shim);
		}

		// check stdin fd
		if (poll_fds[STDIN_INDEX].revents != 0) {
			handle_stdin(&shim);
		}
	}

out:
	free(shim.container_id);
	free(shim.proxy_address);
	free(shim.token);
	if (shim.proxy_sock_fd >= 0) {
		close (shim.proxy_sock_fd);
	}
	return EXIT_FAILURE;
}
