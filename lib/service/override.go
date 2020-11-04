/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package service

import (
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	// import to call client v3 init section
	_ "go.etcd.io/etcd/clientv3"
	"google.golang.org/grpc/grpclog"
)

// setGRPCLogger sets GRPC logger to writer and sets
// severity using env variables from https://pkg.go.dev/google.golang.org/grpc/grpclog
//
// GRPC client logger is pretty verbose, so only call this in debug mode.
//
// etcd client overrides GRPC logger to discard in init
// section. That's why setGRPCLogger is called after etcd client's init
// call and sets it to writer, while taking GRPC standard
// environment variables into account.
func setDebugGRPCLogger(w io.Writer) {
	errorW := ioutil.Discard
	warningW := ioutil.Discard
	infoW := ioutil.Discard

	logLevel := os.Getenv("GRPC_GO_LOG_SEVERITY_LEVEL")

	switch strings.ToLower(logLevel) {
	case "", "error": // If env is unset, set level to ERROR.
		errorW = os.Stderr
	case "warning":
		warningW = os.Stderr
	case "info":
		infoW = os.Stderr
	}

	var v int
	vLevel := os.Getenv("GRPC_GO_LOG_VERBOSITY_LEVEL")
	if vl, err := strconv.Atoi(vLevel); err == nil {
		v = vl
	}

	l := grpclog.NewLoggerV2WithVerbosity(infoW, warningW, errorW, v)
	grpclog.SetLoggerV2(l)
}
