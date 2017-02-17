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

#include <stdio.h>

/* The shim would be handling fixed number of predefined fds.
 * This would be signal fd, stdin fd and a proxy socket connection fd.
 */
#define MAX_POLL_FDS 3

struct cc_shim {
	char       *container_id;
	int         proxy_sock_fd;
	int         proxy_io_fd;
	uint64_t    io_seq_no;
	uint64_t    err_seq_no;
	bool        exiting;
	char       *token;
	char       *proxy_address;
	int         proxy_port;
};

// Header size is length of header in 32 bit words.
#define  MIN_HEADER_WORD_SIZE    3

// Minimum supported proxy version.
#define  PROXY_VERSION        2

// Sizes in bytes
#define  VERSION_SIZE         2
#define  HEADER_LEN_SIZE      1

// Offsets expressed as byte offsets within the header
#define  HEADER_LEN_OFFSET    2
#define  RES_OFFSET           6
#define  OPCODE_OFFSET        7
#define  PAYLOAD_LEN_OFFSET   8
#define  PAYLOAD_OFFSET       12

struct frame_header {
	uint16_t    version;
	uint8_t     header_len;
	uint8_t     err;
	uint8_t     type;
	uint8_t     opcode;
	uint32_t    payload_len; 
};

struct frame {
	struct   frame_header header;
	uint8_t *payload;
};

enum frametype {
	frametype_command = 0,
	frametype_response,
	frametype_stream,
	frametype_notification
};

enum command {
	cmd_registervm = 0,
	cmd_unregistervm,
	cmd_attachvm,
	cmd_hyper,
	cmd_connectshim,
	cmd_disconnectshim,
	cmd_signal,
};

enum stream {
	stream_stdin,
	stream_stdout,
	stream_stderr,
};

enum notificationtype {
	notification_exitcode = 0,
};

/*
 * control message format
 * | ctrl id | length  | payload (length-8)      |
 * | . . . . | . . . . | . . . . . . . . . . . . |
 * 0         4         8                         length
 */
#define CONTROL_HEADER_SIZE             8
#define CONTROL_HEADER_LENGTH_OFFSET    4

/*
 * stream message format
 * | stream sequence | length  | payload (length-12)     |
 * | . . . . . . . . | . . . . | . . . . . . . . . . . . |
 * 0                 8         12                        length
 */
#define STREAM_HEADER_SIZE              12
#define STREAM_HEADER_LENGTH_OFFSET     8

#define PROXY_CTL_HEADER_SIZE           8
#define PROXY_CTL_HEADER_LENGTH_OFFSET  0

/*
 * Hyperstart is limited to sending this number of bytes to
 * a client.
 *
 * (This value can be determined by inspecting the hyperstart
 * source where hyper_event_ops->wbuf_size is set).
 */
#define HYPERSTART_MAX_RECV_BYTES       10240
