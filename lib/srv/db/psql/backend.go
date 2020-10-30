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
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/gravitational/trace"
	"github.com/jackc/pgproto3/v2"
	"github.com/sirupsen/logrus"
)

//
type Backend struct {
	BackendConfig
	*pgproto3.Backend
	logrus.FieldLogger
	conn net.Conn
}

//
type BackendConfig struct {
	Conn       net.Conn
	ServerCert string
	ServerKey  string
	CAPool     *x509.CertPool
}

//
func NewBackend(config BackendConfig) *Backend {
	return &Backend{
		BackendConfig: config,
		Backend:       pgproto3.NewBackend(pgproto3.NewChunkReader(config.Conn), config.Conn),
		FieldLogger:   logrus.WithField("component", "server"),
		conn:          config.Conn,
	}
}

//
type StartupResponse struct {
	StartupMessage *pgproto3.StartupMessage
	Certificate    *x509.Certificate
}

//
func (b *Backend) HandleStartupMessage() (*StartupResponse, error) {
	startupMessage, err := b.ReceiveStartupMessage()
	if err != nil {
		return nil, trace.Wrap(err, "failed to receive startup message")
	}

	b.Debugf("Received startup message: %#v", startupMessage)

	switch message := startupMessage.(type) {
	case *pgproto3.SSLRequest:
		// Reply with S to the client (psql) to indicate we support TLS.
		b.Debug("Replying 'S' to the client")
		_, err = b.conn.Write([]byte("S"))
		if err != nil {
			return nil, trace.Wrap(err, "failed to send 'S' reply to the client")
		}
		// Upgrade the connection.
		b.Debug("Upgrading the connection")
		cert, err := tls.LoadX509KeyPair(b.ServerCert, b.ServerKey)
		if err != nil {
			return nil, trace.Wrap(err, "failed to load server key pair")
		}
		b.conn = tls.Server(b.conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    b.CAPool,
		})
		b.Backend = pgproto3.NewBackend(pgproto3.NewChunkReader(b.conn), b.conn)
		// Wait for the next startup message, should be StartupMessage.
		return b.HandleStartupMessage()

	case *pgproto3.StartupMessage:
		// Extract the identity information from the client certificate.
		if tlsConn, ok := b.conn.(*tls.Conn); ok {
			certs := tlsConn.ConnectionState().PeerCertificates
			if len(certs) == 0 {
				return nil, trace.NotFound("client didn't present any certificates")
			}
			b.Infof("Client presented certificate: SerialNumber[%v] Issuer[%v] Subject[%v]",
				certs[0].SerialNumber, certs[0].Issuer, certs[0].Subject)
			return &StartupResponse{
				StartupMessage: message,
				Certificate:    certs[0],
			}, nil
		}
		return &StartupResponse{
			StartupMessage: message,
		}, nil

	default:
		return nil, trace.BadParameter("unsupported startup message type: %#v", startupMessage)
	}
}

//
func (b *Backend) ExchangeMessages(client *pgproto3.Frontend) {
	defer b.Debug("Exited")
	for {
		b.Debug("Receiving message")
		message, err := b.Receive()
		if err != nil {
			b.WithError(err).Error("Failed to receive message from client")
			return
		}
		b.Debugf("Received message: %#v", message)
		switch msg := message.(type) {
		case *pgproto3.Query:
			b.Infof("---> Executing query %q", msg.String)
		case *pgproto3.Terminate:
			b.Infof("---> Session terminated")
		}
		err = client.Send(message)
		if err != nil {
			b.WithError(err).Error("Failed to send message from client to server")
			return
		}
		b.Debug("Sent message")
		//clientNextMessage <- struct{}{}
		//<-serverNextMessage
	}
}
