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
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
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

const (
	proxyVersion      = 2
	versionOffset     = 0
	headerLenOffset   = 2
	typeOffset        = 6
	opCodeOffset      = 7
	payloadLenOffset  = 8
	payloadOffset     = 12
	proxyHeaderLength = payloadOffset * 8
	minSizeReadBuf    = (2 + 1) * 8
)

type proxyHeader struct {
	version       uint16
	headerLength  uint8
	err           uint8
	frameType     uint8
	opCode        uint8
	payloadLength uint32
}

type proxyFrame struct {
	header  proxyHeader
	payload []byte
}

const (
	frameTypeCommand uint8 = iota
	frameTypeResponse
	frameTypeStream
	frameTypeNotification
)

const (
	cmdRegisterVM uint8 = iota
	cmdUnregisterVM
	cmdAttachVM
	cmdHyper
	cmdConnectShim
	cmdDisconnectShim
	cmdSignal
)

const (
	streamStdin uint8 = iota
	streamStdout
	streamStderr
)

type window struct {
	row    uint16
	col    uint16
	xPixel uint16
	yPixel uint16
}

func sendMessageProxy(conn net.Conn, frameType uint8, opCode uint8, payload string) error {
	frame := proxyFrame{
		header: proxyHeader{
			version:      proxyVersion,
			headerLength: proxyHeaderLength,
			frameType:    frameType,
			opCode:       opCode,
		},
	}

	if payload != "" {
		frame.payload = []byte(payload)
		frame.header.payloadLength = uint32(len(payload))
	}

	logInfo(fmt.Sprintf("Sending frame: %+v", frame))

	totalLength := int(frame.header.headerLength) + int(frame.header.payloadLength)
	frameSlice := make([]byte, totalLength)

	binary.BigEndian.PutUint16(frameSlice[versionOffset:], frame.header.version)
	frameSlice[headerLenOffset] = byte(frame.header.headerLength)
	frameSlice[typeOffset] = byte(frame.header.opCode & 0xF)
	binary.BigEndian.PutUint32(frameSlice[payloadLenOffset:], frame.header.payloadLength)
	copy(frameSlice[payloadOffset:], frame.payload)

	n, err := conn.Write(frameSlice)
	if err != nil {
		return err
	}
	if n != totalLength {
		return fmt.Errorf("Could not send message to proxy")
	}

	return nil
}

func bindProxy(conn net.Conn, token string) error {
	return sendMessageProxy(conn, frameTypeCommand, cmdConnectShim,
		fmt.Sprintf("{\"token\":\"%s\"}", token))
}

func sendSignal(conn net.Conn, signal os.Signal) error {
	payload := fmt.Sprintf("{\"signalNumber\":%d}", signal)

	if signal == syscall.SIGWINCH {
		w := new(window)
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
			os.Stdin.Fd(),
			syscall.TIOCGWINSZ,
			uintptr(unsafe.Pointer(&w)),
		); errno != 0 {
			return error(errno)
		}

		payload = fmt.Sprintf("{\"signalNumber\":%d,\"rows\":%d,\"columns\":%d}",
			signal, w.row, w.col)
	}

	return sendMessageProxy(conn, frameTypeCommand, cmdSignal, payload)
}

func sendStdin(conn net.Conn, msg string) error {
	return sendMessageProxy(conn, frameTypeStream, streamStdin, msg)
}

func readFrameProxy(conn net.Conn) (proxyFrame, error) {
	frameBuf := []byte{}

	buf, err := readBytesLen(conn, minSizeReadBuf)
	if err != nil {
		return proxyFrame{}, err
	}

	frameBuf = append(frameBuf, buf...)

	headerLen := int(frameBuf[headerLenOffset])
	remainingHeaderLen := headerLen - minSizeReadBuf

	if remainingHeaderLen < 0 {
		return proxyFrame{}, fmt.Errorf("Invalid header length %d", headerLen)
	} else if remainingHeaderLen == 0 {
		return proxyFrame{
			header: proxyHeader{
				version:      binary.BigEndian.Uint16(frameBuf[:headerLenOffset]),
				headerLength: uint8(frameBuf[headerLenOffset]),
			},
		}, nil
	}

	buf, err = readBytesLen(conn, remainingHeaderLen)
	if err != nil {
		return proxyFrame{}, err
	}

	frameBuf = append(frameBuf, buf...)

	return proxyFrame{}, nil
}

func readBytesLen(conn net.Conn, length int) ([]byte, error) {
	needRead := length
	read := 0
	buf := make([]byte, 512)
	res := []byte{}
	for read < needRead {
		want := needRead - read
		if want > 512 {
			want = 512
		}
		nr, err := conn.Read(buf[:want])
		if err != nil {
			return nil, err
		}

		res = append(res, buf[:nr]...)
		read = read + nr
	}

	return res, nil
}
