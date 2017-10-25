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
	"log"
	"log/syslog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"

	"github.com/clearcontainers/proxy/api"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
)

const (
	childProcessName = "shim-child"
	endByte          = 'E'
)

var shimLog *log.Logger
var debugFlag bool

type shim struct {
	params       shimParams
	conn         net.Conn
	pipeChild    *os.File
	frameCh      chan *api.Frame
	stdinCh      chan []byte
	signalCh     chan os.Signal
	errCh        chan error
	termios      unix.Termios
	savedTermios bool
	lock         sync.Mutex
	hasToExit    bool
	exitCode     int
}

type shimParams struct {
	cid   string
	token string
	uri   url.URL
	debug bool
}

func initSyslog() (err error) {
	shimLog, err = syslog.NewLogger(syslog.LOG_INFO, log.Ltime)
	return
}

func logDebug(msg interface{}) {
	if debugFlag {
		return
	}

	shimLog.Printf("DEBUG: %v", msg)
}

func logInfo(msg interface{}) {
	shimLog.Printf("INFO: %v", msg)
}

func logWarn(msg interface{}) {
	shimLog.Printf("WARN: %v", msg)
}

func logError(msg interface{}) {
	shimLog.Printf("ERROR: %v", msg)
}

func parseCLIParams(context *cli.Context) (shimParams, error) {
	cid := context.String("container-id")
	if cid == "" {
		return shimParams{}, fmt.Errorf("Empty container ID")
	}

	token := context.String("token")
	if token == "" {
		return shimParams{}, fmt.Errorf("Empty token")
	}

	uri := context.String("uri")
	if uri == "" {
		return shimParams{}, fmt.Errorf("Empty URI")
	}
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return shimParams{}, fmt.Errorf("Could not parse URI %q: %v", uri, err)
	}

	return shimParams{
		cid:   cid,
		token: token,
		uri:   *parsedURI,
		debug: context.Bool("debug"),
	}, nil
}

func (s *shim) connectURI() error {
	logInfo(fmt.Sprintf("URI provided: %+v", s.params.uri))

	conn, err := net.Dial(s.params.uri.Scheme, s.params.uri.Path)
	if err != nil {
		return err
	}

	s.conn = conn

	return nil
}

func (s *shim) disconnectURI() error {
	defer func() {
		s.conn = nil
	}()

	if s.conn == nil {
		return nil
	}

	return s.conn.Close()
}

func isTerminal(fd uintptr) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&termios)))

	return err == 0
}

func (s *shim) setupTerminal() error {
	if !isTerminal(os.Stdin.Fd()) {
		return nil
	}

	var termios unix.Termios

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, os.Stdin.Fd(), unix.TCGETS, uintptr(unsafe.Pointer(&termios))); err != 0 {
		return fmt.Errorf("Could not get tty info: %s", err.Error())
	}

	s.termios = termios
	s.savedTermios = true

	// Set the terminal in raw mode
	termios.Iflag &^= (unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON)
	termios.Oflag &^= unix.OPOST
	termios.Lflag &^= (unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN)
	termios.Cflag &^= (unix.CSIZE | unix.PARENB)
	termios.Cflag |= unix.CS8
	termios.Cc[unix.VMIN] = 1
	termios.Cc[unix.VTIME] = 0

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, os.Stdin.Fd(), unix.TCSETS, uintptr(unsafe.Pointer(&termios))); err != 0 {
		return fmt.Errorf("Could not set tty in raw mode: %s", err.Error())
	}

	return nil
}

func (s *shim) restoreTerminal() error {
	if !isTerminal(os.Stdin.Fd()) {
		return nil
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, os.Stdin.Fd(), unix.TCSETS, uintptr(unsafe.Pointer(&s.termios))); err != 0 {
		return fmt.Errorf("Could not restore tty settings: %s", err.Error())
	}

	return nil
}

func (s *shim) spawnChildWatchdog() error {
	var connFile *os.File
	var err error

	switch conn := s.conn.(type) {
	case *net.TCPConn:
		connFile, err = conn.File()
		if err != nil {
			return err
		}
	case *net.UnixConn:
		connFile, err = conn.File()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Unknown net.Conn type")
	}

	child, parent, err := os.Pipe()
	if err != nil {
		return err
	}
	defer child.Close()

	s.pipeChild = parent

	cmd := exec.Cmd{
		Path:        "/proc/self/exe",
		Args:        []string{childProcessName},
		ExtraFiles:  []*os.File{child, connFile},
	}

	logInfo(fmt.Sprintf("Parent PID %d", os.Getpid()))

	if err := cmd.Start(); err != nil {
		return err
	}

	if err := json.NewEncoder(s.pipeChild).Encode(s.termios); err != nil {
		return err
	}

	return nil
}

func (s *shim) setupSignals() error {
	s.signalCh = make(chan os.Signal)

	signal.Notify(s.signalCh)

	return nil
}

func (s *shim) setupProxyMessages() error {
	s.frameCh = make(chan *api.Frame)

	go func() {
		for {
			frame, err := api.ReadFrame(s.conn)
			if err != nil {
				if err == io.EOF {
					break
				}

				s.errCh <- err
			}

			if frame == nil {
				s.errCh <- fmt.Errorf("Frame retrieved is nil")
			}

			s.frameCh <- frame
		}
	}()

	return nil
}

func (s *shim) setupStdin() error {
	s.stdinCh = make(chan []byte)

	go func() {
		for {
			buf := make([]byte, 512)
			n, err := os.Stdin.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}

				s.errCh <- err
			}

			logDebug(fmt.Sprintf("Read %q from STDIN", string(buf[:n])))
			s.stdinCh <- buf[:n]
		}
	}()

	return nil
}

func initialize(context *cli.Context) (*shim, error) {
	logInfo("Shim initialize: start")
	defer logInfo("Shim initialize: end")

	shimParams, err := parseCLIParams(context)
	if err != nil {
		return nil, err
	}

	if shimParams.debug {
		debugFlag = true
	}

	return &shim{
		params: shimParams,
	}, nil
}

func (s *shim) setup() error {
	logInfo("Shim setup: start")
	defer logInfo("Shim setup: end")

	// Connect URI
	if err := s.connectURI(); err != nil {
		return err
	}

	// Connect proxy
	if err := s.connectProxy(); err != nil {
		return err
	}

	// Setup terminal
	if err := s.setupTerminal(); err != nil {
		return err
	}

	// Spawn child process to watchdog the parent. This is needed for the
	// specific case of SIGKILL and SIGSTOP since those signals cannot be
	// caught by the current process.
	if err := s.spawnChildWatchdog(); err != nil {
		return err
	}

	// Setup signals
	if err := s.setupSignals(); err != nil {
		return err
	}

	// Setup proxy messages read loop
	if err := s.setupProxyMessages(); err != nil {
		return err
	}

	// Setup STDIN read loop
	return s.setupStdin()
}

func (s *shim) mainLoop() error {
	logInfo("Shim mainLoop: start")
	defer logInfo("Shim mainLoop: end")
	for {
		select {
		case frame := <-s.frameCh:
			if err := s.handleProxyFrame(frame); err != nil {
				return err
			}
		case sig := <-s.signalCh:
			if err := s.handleSignal(sig); err != nil {
				return err
			}
		case input := <-s.stdinCh:
			if err := s.handleStdin(input); err != nil {
				return err
			}
		case err := <-s.errCh:
			return err
		}

		if s.hasToExit {
			break
		}
	}

	return nil
}

func (s *shim) teardown() error {
	logInfo("Shim teardown: start")
	defer logInfo("Shim teardown: end")

	if err := s.disconnectProxy(); err != nil {
		return err
	}

	return s.disconnectURI()
}

func (s *shim) exit() {
	logInfo("Shim parent exits")

	// Un-assign all signals. They are no longer routed to
	// shim.signalCh channel
	signal.Reset()

	if s.pipeChild != nil {
		s.pipeChild.Write([]byte{endByte})
	}

	if s.savedTermios {
		s.restoreTerminal()
	}

	os.Exit(s.exitCode)
}

func isRunningChild() bool {
	if os.Args[0] == childProcessName {
		return true
	}

	return false
}

func main() {
	if err := initSyslog(); err != nil {
		os.Exit(1)
	}

	if isRunningChild() {
		if err := mainChild(); err != nil {
			logError(err)
			os.Exit(1)
		}

		return
	}

	// Read flags from CLI
	cli.VersionFlag = cli.BoolFlag{
		Name:  "version, v",
		Usage: "Show version",
	}

	shimCLI := cli.NewApp()
	shimCLI.Name = "Shim CLI"
	shimCLI.Version = "0.0.1"

	shimCLI.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "container-id, c",
			Value: "",
			Usage: "Container id",
		},
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "Enable debug output",
		},
		cli.StringFlag{
			Name:  "token, t",
			Value: "",
			Usage: "Connection token passed by cc-proxy",
		},
		cli.StringFlag{
			Name:  "uri, u",
			Value: "",
			Usage: "Connection uri. Supported schemes are tcp: and unix:",
		},
	}

	shimCLI.Action = func(context *cli.Context) (err error) {
		s, err := initialize(context)
		if err != nil {
			logError(err)
			return
		}
		defer s.exit()

		if err = s.setup(); err != nil {
			logError(err)
			return
		}

		if err = s.mainLoop(); err != nil {
			logError(err)
			return
		}

		if err = s.teardown(); err != nil {
			logError(err)
			return
		}

		return nil
	}

	if err := shimCLI.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
