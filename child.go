// Copyright (c) 2017 Intel Corporation
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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

func teardownOnParentBehalf(conn net.Conn, termios unix.Termios) error {
	logInfo("Shim child has to teardown on behalf of parent")

	shim := &shim{
		conn:    conn,
		termios: termios,
	}

	defer shim.restoreTerminal()

	// Send SIGKILL to proxy
	if err := shim.handleSignal(syscall.SIGKILL); err != nil {
		return err
	}

	// Cleanup
	if err := shim.teardown(); err != nil {
		return err
	}

	return nil
}

func mainChild() error {
	logInfo(fmt.Sprintf("Child PID %d", os.Getpid()))
	defer logInfo("Shim child exits")

	// This avoid the child process to be terminated when the parent dies.
	signal.Ignore()

	// Those file descriptors must be in sync with the order chosen by the
	// parent process.
	pipeParent := os.NewFile(uintptr(3), "pipe")
	connFile := os.NewFile(uintptr(4), "uriConn")

	conn, err := net.FileConn(connFile)
	if err != nil {
		return err
	}

	// Retrieve the termios structure if this process needs to restore
	// the terminal state.
	var termios unix.Termios
	if err := json.NewDecoder(pipeParent).Decode(&termios); err != nil {
		return err
	}

	// Wait for the parent process to send the termination byte. In case
	// no byte is received, this means the parent could not send this byte
	// because it has been killed by a SIGKILL signal. The child has to
	// send this signal on behalf of the parent.
	buf := make([]byte, 1)
	n, err := pipeParent.Read(buf)
	if err != nil && err != io.EOF {
		return err
	}

	if n > 0 && buf[0] == endByte {
		return nil
	}

	return teardownOnParentBehalf(conn, termios)
}
