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
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/clearcontainers/shim/mock"
	hypermock "github.com/containers/virtcontainers/hyperstart/mock"
	"github.com/stretchr/testify/assert"
)

type testRig struct {
	t *testing.T

	// wait for the shim to finish
	wg sync.WaitGroup

	//Mock Proxy
	proxy *mock.Proxy

	//shim forked
	shimCommand *exec.Cmd

	shimStdin  io.WriteCloser
	shimStdout io.ReadCloser
	shimStderr io.ReadCloser
}

func newTestRig(t *testing.T) *testRig {
	return &testRig{
		t: t,
	}
}

const testContainerid = "123456789"

type tokenType int

const (
	validToken = iota

	//Token in base64url encoding, but not the same as proxy
	incorrectToken

	//Token provided not in base64 encoding
	invalidToken
)

var shimPath string

func TestMain(m *testing.M) {
	flag.StringVar(&shimPath, "shimpath", "/usr/libexec/cc-shim",
		"absolute path to the cc-shim executable")
	flag.Parse()
	fmt.Printf("Path of cc-shim executable : %s\n", shimPath)
	os.Exit(m.Run())
}

func (rig *testRig) Start(tokenT tokenType) {
	var token string

	proxySocketPath := hypermock.GetTmpPath("test-proxy.%s.sock")
	rig.proxy = mock.NewProxy(rig.t, proxySocketPath)
	rig.proxy.Start()

	url := url.URL{
		Scheme: "unix",
		Path:   proxySocketPath,
	}

	if tokenT == invalidToken {
		token = "testtoken"
	} else if tokenT == incorrectToken {
		token = "RidbiogVs8QCbta0uj2FJRjjnLcPagpqjZceJKvu4MA="
	} else {
		token = rig.proxy.GetProxyToken()
	}

	assert.NotNil(rig.t, token)

	rig.shimCommand = rig.getShimCommand(url.String(), token)
	err := rig.shimCommand.Start()
	assert.Nil(rig.t, err)
	rig.t.Logf("shim started\n")
}

func (rig *testRig) getShimCommand(uri string, token string) *exec.Cmd {
	var err error

	args := []string{
		"--container-id", testContainerid,
		"--uri", uri,
		"--token", token,
		//"--debug",
	}

	cmd := exec.Command(shimPath, args...)
	rig.shimStdin, err = cmd.StdinPipe()
	assert.Nil(rig.t, err)
	rig.shimStdout, err = cmd.StdoutPipe()
	assert.Nil(rig.t, err)
	rig.shimStderr, err = cmd.StderrPipe()
	assert.Nil(rig.t, err)

	return cmd
}

func (rig *testRig) Stop() {
	cmd := rig.shimCommand

	if cmd.Process != nil {
		syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
		rig.t.Logf("Shim process killed!")
	}

	rig.proxy.Stop()
}

func (rig *testRig) checkShimRunning() error {
	cmd := rig.shimCommand
	assert.NotNil(rig.t, cmd.Process)

	err := syscall.Kill(cmd.Process.Pid, syscall.Signal(0))
	if err != nil {
		rig.t.Logf("Shim has exited early: %v\n", err)
	}

	return err
}

func TestShimConnectToProxy(t *testing.T) {
	rig := newTestRig(t)
	//rig.Start(tokenType(validToken))
	rig.Start(validToken)
	assert.NotNil(t, rig.proxy)

	defer rig.Stop()

	//Check that shim is running with the command line options provided
	time.Sleep(500 * time.Millisecond)
	err := rig.checkShimRunning()
	if err != nil {
		t.Fatal(err)
	}

	//Wait for shim to connect to proxy
	<-rig.proxy.ShimConnected
}

func TestShimExitWithIncorrectBase64Token(t *testing.T) {
	rig := newTestRig(t)
	rig.Start(incorrectToken)
	assert.NotNil(t, rig.proxy)

	defer rig.Stop()

	//Shim should have sent connect
	<-rig.proxy.ShimConnected

	//Wait for shim to connect to exit
	cmd := rig.shimCommand
	assert.NotNil(rig.t, cmd.Process)
	err := cmd.Wait()
	assert.NotNil(rig.t, err)

	processState := cmd.ProcessState
	assert.NotNil(rig.t, processState)
	ws := processState.Sys().(syscall.WaitStatus)
	assert.NotNil(rig.t, ws)
	exitCode := ws.ExitStatus()
	assert.Equal(rig.t, exitCode, 1)
}

func TestShimExitWithNonBase64Token(t *testing.T) {
	rig := newTestRig(t)
	rig.Start(invalidToken)
	assert.NotNil(t, rig.proxy)

	defer rig.Stop()

	//Wait for shim to connect to exit
	cmd := rig.shimCommand
	assert.NotNil(rig.t, cmd.Process)
	err := cmd.Wait()
	assert.NotNil(rig.t, err)

	timedout := false
	timer := make(chan bool, 1)
	go func() {
		time.Sleep(500 * time.Millisecond)
		timer <- true
	}()

	select {
	case <-rig.proxy.ShimConnected:
		// Shim sent connect msg to proxy!
	case <-timer:
		timedout = true
	}
	assert.Equal(rig.t, timedout, true)

	processState := cmd.ProcessState
	assert.NotNil(rig.t, processState)
	ws := processState.Sys().(syscall.WaitStatus)
	assert.NotNil(rig.t, ws)
	exitCode := ws.ExitStatus()
	assert.Equal(rig.t, exitCode, 1)
}

func TestShimStdout(t *testing.T) {
	rig := newTestRig(t)
	rig.Start(validToken)
	assert.NotNil(t, rig.proxy)

	defer rig.Stop()

	err := rig.checkShimRunning()
	assert.Nil(rig.t, err)
	<-rig.proxy.ShimConnected

	payload := []byte("Test stdout")

	rig.proxy.SendStdoutStream(payload)

	buf := make([]byte, 512)
	n, err := rig.shimStdout.Read(buf)
	assert.Nil(t, err)
	assert.Equal(rig.t, payload, buf[0:len(payload)])

	s := string(buf[:n])
	t.Logf("Stdout buffer received from proxy: %s\n", s)
}

func TestShimStderr(t *testing.T) {
	rig := newTestRig(t)
	rig.Start(validToken)
	assert.NotNil(t, rig.proxy)

	defer rig.Stop()

	err := rig.checkShimRunning()
	assert.Nil(rig.t, err)
	<-rig.proxy.ShimConnected

	payload := []byte("Test string for stderr.")
	rig.proxy.SendStderrStream(payload)

	buf := make([]byte, 1024)
	n, err := rig.shimStderr.Read(buf)
	assert.Nil(t, err)

	s := string(buf[:n])
	rig.t.Logf("Stderr buffer received from proxy: %s\n", s)
	assert.Equal(rig.t, payload, buf[0:len(payload)])
}

func TestShimSignals(t *testing.T) {
	rig := newTestRig(t)
	rig.Start(validToken)
	assert.NotNil(t, rig.proxy)

	defer rig.Stop()

	err := rig.checkShimRunning()
	assert.Nil(rig.t, err)
	<-rig.proxy.ShimConnected

	numSignal := 0
	select {
	case <-rig.proxy.Signal:
		numSignal++
	default:
		t.Logf("No signals received yet")
	}
	assert.Equal(rig.t, numSignal, 0)

	cmd := rig.shimCommand
	assert.NotNil(rig.t, cmd.Process)
	err = syscall.Kill(cmd.Process.Pid, syscall.SIGUSR1)
	assert.Nil(rig.t, err)

	sig := <-rig.proxy.Signal
	assert.Equal(rig.t, syscall.Signal(sig.Signal), syscall.SIGUSR1)
}

func TestShimExitNotification(t *testing.T) {
	rig := newTestRig(t)
	rig.Start(validToken)
	assert.NotNil(t, rig.proxy)

	defer rig.Stop()

	err := rig.checkShimRunning()
	assert.Nil(rig.t, err)
	<-rig.proxy.ShimConnected

	payload := make([]byte, 1)
	payload[0] = 127
	rig.proxy.SendExitNotification(payload)

	cmd := rig.shimCommand
	assert.NotNil(rig.t, cmd.Process)
	err = cmd.Wait()
	assert.NotNil(rig.t, err)

	<-rig.proxy.ShimDisconnected

	processState := cmd.ProcessState
	assert.NotNil(rig.t, processState)
	ws := processState.Sys().(syscall.WaitStatus)
	assert.NotNil(rig.t, ws)
	exitCode := ws.ExitStatus()
	assert.Equal(rig.t, exitCode, 127)
}

func TestShimSendingStdin(t *testing.T) {
	rig := newTestRig(t)
	rig.Start(validToken)
	assert.NotNil(t, rig.proxy)

	defer rig.Stop()

	err := rig.checkShimRunning()
	assert.Nil(rig.t, err)
	<-rig.proxy.ShimConnected

	stdinStream := rig.proxy.GetLastStdinStream()
	assert.Nil(rig.t, stdinStream)

	input := []byte("Test input for proxy")
	n, err := rig.shimStdin.Write(input)
	assert.Nil(rig.t, err)
	assert.Equal(rig.t, n, len(input))

	<-rig.proxy.StdinReceived
	stdinStream = rig.proxy.GetLastStdinStream()
	assert.Equal(rig.t, stdinStream, input)
}
