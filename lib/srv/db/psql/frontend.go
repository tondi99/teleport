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

package psql

import (
	"context"
	"fmt"

	"github.com/gravitational/trace"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"github.com/sirupsen/logrus"
)

//
type Frontend struct {
	*pgproto3.Frontend
	logrus.FieldLogger
}

//
type FrontendConfig struct {
	RemoteAddr     string
	StartupMessage *pgproto3.StartupMessage
	ClientCert     string
	ClientKey      string
	CACert         string
}

//
func NewFrontend(ctx context.Context, config FrontendConfig) (*Frontend, error) {
	// Create connect config.
	connString := fmt.Sprintf("postgres://xxx@%s/?sslmode=verify-full&sslcert=%s&sslkey=%s&sslrootcert=%s",
		config.RemoteAddr, config.ClientCert, config.ClientKey, config.CACert)
	connectConfig, err := pgconn.ParseConfig(connString)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	connectConfig.Database = config.StartupMessage.Parameters["database"]
	connectConfig.User = config.StartupMessage.Parameters["user"]

	// Connect to the backend database.
	conn, err := pgconn.ConnectConfig(ctx, connectConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	client := &Frontend{
		Frontend:    pgproto3.NewFrontend(pgproto3.NewChunkReader(conn.Conn()), conn.Conn()),
		FieldLogger: logrus.WithField("component", "client"),
	}

	client.Infof("Connected to database %q as user %q", connectConfig.Database, connectConfig.User)
	return client, nil
}

//
func (f *Frontend) ExchangeMessages(server *pgproto3.Backend) {
	defer f.Debug("Exited")
	for {
		f.Debug("Receiving message")
		message, err := f.Receive()
		if err != nil {
			f.WithError(err).Error("Failed to receive message from server")
			return
		}
		f.Debugf("Received message: %#v", message)
		switch msg := message.(type) {
		case *pgproto3.ErrorResponse:
			f.Warnf("<--- Query completed with error %q", msg.Message)
		case *pgproto3.DataRow:
			f.Infof("<--- Query returned data row with %v columns", len(msg.Values))
		case *pgproto3.CommandComplete:
			f.Infof("<--- Query completed")
		}
		err = server.Send(message)
		if err != nil {
			f.WithError(err).Error("Failed to send message from server to client")
			return
		}
		f.Debug("Sent message")
	}
}
