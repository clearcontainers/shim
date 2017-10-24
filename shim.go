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
	"fmt"
	"log"
	"log/syslog"
	"net"
	"net/url"
	"os"

	"github.com/urfave/cli"
)

var shimLog *log.Logger

type shim struct {
	params shimParams
	conn   net.Conn
}

type shimParams struct {
	cid   string
	token string
	uri   url.URL
	debug bool
}

func logDebug(msg interface{}) {
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
	conn, err := net.Dial(s.params.uri.Scheme, s.params.uri.Host)
	if err != nil {
		return err
	}

	s.conn = conn

	return nil
}

func initialize(context *cli.Context) (*shim, error) {
	var err error

	// Initialize system logs
	shimLog, err = syslog.NewLogger(syslog.LOG_INFO, log.Ltime)
	if err != nil {
		return nil, err
	}

	logInfo("Shim initialized")

	shimParams, err := parseCLIParams(context)
	if err != nil {
		return nil, err
	}

	return &shim{
		params: shimParams,
	}, nil
}

func (s *shim) setup() error {
	// Connect URI
	if err := s.connectURI(); err != nil {
		return err
	}

	// Connect proxy
	if err := bindProxy(s.conn, s.params.token); err != nil {
		return err
	}

	return nil
}

func main() {
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

	shimCLI.Action = func(context *cli.Context) error {
		shim, err := initialize(context)
		if err != nil {
			logError(err)
			return err
		}

		if err := shim.setup(); err != nil {
			logError(err)
			return err
		}

		return nil
	}

	if err := shimCLI.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
