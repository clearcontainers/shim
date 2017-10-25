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
	"os"
	"syscall"
	"unsafe"

	"github.com/clearcontainers/proxy/api"
)

/* 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 * ┌────────────────────────────┬───────────────┬───────────────┐
 * │          Version           │ Header Length │   Reserved    │
 * ├────────────────────────────┼─────┬─┬───────┼───────────────┤
 * │          Reserved          │ Res.│E│ Type  │    Opcode     │
 * ├────────────────────────────┴─────┴─┴───────┴───────────────┤
 * │                      Payload Length                        │
 * ├────────────────────────────────────────────────────────────┤
 * │                                                            │
 * │                         Payload                            │
 * │                                                            │
 * │      (variable length, optional and opcode-specific)       │
 * │                                                            │
 * └────────────────────────────────────────────────────────────┘
 */

type window struct {
	row    uint16
	col    uint16
	xPixel uint16
	yPixel uint16
}

func (s *shim) connectProxy() error {
	payload := api.ConnectShim{
		Token: s.params.token,
	}

	payloadBuf, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	return api.WriteCommand(s.conn, api.CmdConnectShim, payloadBuf)
}

func (s *shim) disconnectProxy() error {
	payload := api.DisconnectShim{}

	payloadBuf, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	return api.WriteCommand(s.conn, api.CmdDisconnectShim, payloadBuf)
}

func (s *shim) handleSignal(signal os.Signal) error {
	sig, ok := signal.(syscall.Signal)
	if !ok {
		return fmt.Errorf("Could not cast the signal %q", signal.String())
	}

	payload := api.Signal{
		SignalNumber: int(sig),
	}

	if sig == syscall.SIGWINCH {
		w := window{}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
			os.Stdin.Fd(),
			syscall.TIOCGWINSZ,
			uintptr(unsafe.Pointer(&w)),
		); errno != 0 {
			return error(errno)
		}

		payload.Columns = int(w.col)
		payload.Rows = int(w.row)
	}

	payloadBuf, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	return api.WriteCommand(s.conn, api.CmdSignal, payloadBuf)
}

func (s *shim) handleStdin(payload []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	return api.WriteStream(s.conn, api.StreamStdin, payload)
}

func (s *shim) handleProxyFrame(frame *api.Frame) error {
	switch frame.Header.Type {
	case api.TypeCommand:
		return fmt.Errorf("Proxy should not send command")
	case api.TypeResponse:
		return s.handleProxyResponse(frame)
	case api.TypeStream:
		return s.handleProxyStream(frame)
	case api.TypeNotification:
		return s.handleProxyNotif(frame)
	default:
		return fmt.Errorf("Unknown frame type %d", frame.Header.Type)
	}
}

func (s *shim) handleProxyResponse(frame *api.Frame) error {
	if frame.Header.InError {
		if frame.Header.Opcode == int(api.CmdConnectShim) {
			logError("Error response received from proxy on ConnectShim command")
			return fmt.Errorf("ConnectShim command failed")
		}

		logWarn("Error response received from proxy")

		// Ignore error received if it's not caused by shim connection.
		return nil
	}

	logInfo(fmt.Sprintf("Response from proxy %q", string(frame.Payload)))

	return nil
}

func (s *shim) handleProxyStream(frame *api.Frame) error {
	var outFd *os.File

	if frame.Header.Opcode == int(api.StreamStdout) {
		outFd = os.Stdout
	} else if frame.Header.Opcode == int(api.StreamStderr) {
		outFd = os.Stderr
	} else {
		logWarn(fmt.Sprintf("Invalid stream opcode %d", frame.Header.Opcode))
		return nil
	}

	_, err := outFd.Write(frame.Payload)
	if err != nil {
		return err
	}

	return nil
}

func (s *shim) handleProxyNotif(frame *api.Frame) error {
	if frame.Header.Opcode == api.NotificationProcessExited {
		s.exitCode = int(frame.Payload[0])
		s.hasToExit = true
		return nil
	}

	logWarn(fmt.Sprintf("Unknown notif opcode %d", frame.Header.Opcode))
	return nil
}
