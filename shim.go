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
	"log"
	"log/syslog"
	"os"

	"github.com/urfave/cli"
)

var shimLog *log.Logger

func initialize(c *cli.Context) (err error) {
	// Initialize system logs
	shimLog, err = syslog.NewLogger(syslog.LOG_INFO, log.Ltime)
	if err != nil {
		return err
	}

	shimLog.Print("Shim initialized")

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

	shimCLI.Action = func(c *cli.Context) error {
		if err := initialize(c); err != nil {
			return err
		}

		return nil
	}

	if err := shimCLI.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
