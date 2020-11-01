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

package db

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/auth/proto"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jackc/pgproto3/v2"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

//
type ProxyServer struct {
	ProxyServerConfig
	logrus.FieldLogger
}

//
type ProxyServerConfig struct {
	// AccessPoint is the caching client connected to the auth server.
	AccessPoint auth.AccessPoint
	//
	AuthClient *auth.Client
	// Tunnel is the reverse tunnel server.
	Tunnel reversetunnel.Server
	//
	TLSConfig *tls.Config
}

// CheckAndSetDefaults validates the config and sets default values.
func (c *ProxyServerConfig) CheckAndSetDefaults() error {
	if c.AccessPoint == nil {
		return trace.BadParameter("missing AccessPoint")
	}
	if c.AuthClient == nil {
		return trace.BadParameter("missing AuthClient")
	}
	if c.Tunnel == nil {
		return trace.BadParameter("missing Tunnel")
	}
	if c.TLSConfig == nil {
		return trace.BadParameter("missing TLSConfig")
	}
	return nil
}

//
func NewProxyServer(config ProxyServerConfig) (*ProxyServer, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	server := &ProxyServer{
		ProxyServerConfig: config,
		FieldLogger:       logrus.WithField(trace.Component, "proxy:db"),
	}
	// TODO(r0mant): Copy TLS config?
	server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	server.TLSConfig.GetConfigForClient = server.getConfigForClient
	return server, nil
}

//
func (s *ProxyServer) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			s.WithError(err).Error("Failed to accept connection.")
			continue
		}
		s.Debugf("Accepted connection from %v.", conn.RemoteAddr())
		go func() {
			if err := s.handleConnection(context.TODO(), conn); err != nil {
				s.WithError(err).Error("Failed to handle connection.")
			}
		}()
	}
	return nil
}

func extractIdentity(conn net.Conn, log logrus.FieldLogger) (*tlsca.Identity, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, trace.BadParameter("expected tls connection, got %T", conn)
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, trace.NotFound("client didn't present any certificates")
	}
	log.Infof("Client presented certificate: SerialNumber[%v] Issuer[%v] Subject[%v].",
		certs[0].SerialNumber, certs[0].Issuer, certs[0].Subject)
	identity, err := tlsca.FromSubject(certs[0].Subject, certs[0].NotAfter)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	log.Infof("Client identity: %#v.", identity)
	return identity, nil
}

//
func (s *ProxyServer) handleConnection(ctx context.Context, conn net.Conn) error {
	backend := pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)

	startupMessage, err := backend.ReceiveStartupMessage()
	if err != nil {
		return trace.Wrap(err)
	}
	s.Debugf("Received startup message: %#v.", startupMessage)

	switch message := startupMessage.(type) {
	case *pgproto3.SSLRequest:
		// Reply with S to the client (psql) to indicate we support TLS.
		s.Debug("Replying 'S' to the client")
		_, err = conn.Write([]byte("S"))
		if err != nil {
			return trace.Wrap(err, "failed to send 'S' reply to the client")
		}

		// Upgrade the connection.
		conn = tls.Server(conn, s.TLSConfig)

		// Wait for the next startup message, should be StartupMessage.
		return s.handleConnection(ctx, conn)

	case *pgproto3.StartupMessage:
		// Extract the identity information from the client certificate.
		identity, err := extractIdentity(conn, s.FieldLogger)
		if err != nil {
			return trace.Wrap(err)
		}

		// tlsConn, ok := conn.(*tls.Conn)
		// if !ok {
		// 	return nil
		// }

		// certs := tlsConn.ConnectionState().PeerCertificates
		// if len(certs) == 0 {
		// 	return trace.NotFound("client didn't present any certificates")
		// }

		// s.Infof("Client presented certificate: SerialNumber[%v] Issuer[%v] Subject[%v]",
		// 	certs[0].SerialNumber, certs[0].Issuer, certs[0].Subject)

		// identity, err := tlsca.FromSubject(certs[0].Subject, certs[0].NotAfter)
		// if err != nil {
		// 	return trace.Wrap(err)
		// }

		// s.Infof("Client identity: %#v", identity)

		// TODO(r0mant): Add authorization.

		// TODO(r0mant): Add proper routing via RouteToDatabase identity field.

		sites := s.Tunnel.GetSites()
		s.Debugf("Available sites: %#v", sites)
		site := sites[0]
		s.Debugf("Using site: %#v", site)

		dbServers, err := s.AccessPoint.GetDatabaseServers(ctx, defaults.Namespace)
		if err != nil {
			return trace.Wrap(err)
		}
		s.Debugf("Available database servers: %#v", dbServers)
		dbServer := dbServers[0]
		s.Debugf("Using database server: %#v", dbServer)

		dbs := dbServer.GetDatabases()
		s.Debugf("Available databases: %#v", dbs)
		db := dbs[0]
		s.Debugf("Using database: %#v", db)

		// s.Debug("Generating user cert")
		// _, publicKey, err := native.GenerateKeyPair("")
		// if err != nil {
		// 	return trace.Wrap(err)
		// }
		// userCerts, err := s.AuthClient.GenerateUserCerts(context.TODO(), proto.UserCertsRequest{
		// 	PublicKey: publicKey,
		// 	Username:  identity.Username,
		// 	Expires:   identity.Expires,
		// })
		// if err != nil {
		// 	return trace.Wrap(err)
		// }
		// s.Debugf("Generated user certs: %#v", userCerts)

		tlsConfig, err := s.getConfigForServer(ctx, identity, dbServer)
		if err != nil {
			return trace.Wrap(err)
		}

		siteConn, err := site.Dial(reversetunnel.DialParams{
			From:     &utils.NetAddr{AddrNetwork: "tcp", Addr: "@db-proxy"},
			To:       &utils.NetAddr{AddrNetwork: "tcp", Addr: fmt.Sprintf("@db-%v", db.Name)},
			ServerID: fmt.Sprintf("%v.%v", dbServer.GetName(), site.GetName()),
			ConnType: services.DatabaseTunnel,
		})
		if err != nil {
			return trace.Wrap(err)
		}

		siteConn = tls.Client(siteConn, tlsConfig)

		// Pass along the startup message.
		frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(siteConn), siteConn)
		err = frontend.Send(message)
		if err != nil {
			return trace.Wrap(err)
		}

		go io.Copy(siteConn, conn)
		_, err = io.Copy(conn, siteConn)
		if err != nil {
			return trace.Wrap(err)
		}

		return nil

	default:
		return trace.BadParameter("unsupported startup message type: %#v", startupMessage)
	}
}

// getConfigForServer returns TLS config used for establishing connection
// to a remote database server over reverse tunnel.
func (s *ProxyServer) getConfigForServer(ctx context.Context, identity *tlsca.Identity, server services.Server) (*tls.Config, error) {
	privateKeyBytes, _, err := native.GenerateKeyPair("")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	privateKey, err := ssh.ParseRawPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	subject, err := identity.Subject()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	csr := &x509.CertificateRequest{
		Subject: subject,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	cluster, err := s.AuthClient.GetClusterName() // TODO(r0mant): Extract cluster name from identity.
	if err != nil {
		return nil, trace.Wrap(err)
	}
	response, err := s.AuthClient.SignDatabaseCSR(ctx, &proto.SignDatabaseCSRRequest{
		CSR:         csrPEM,
		ClusterName: cluster.GetClusterName(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cert, err := tls.X509KeyPair(response.Cert, privateKeyBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.Debug("Generated database certificate.")
	pool := x509.NewCertPool()
	for _, caCert := range response.CACerts {
		ok := pool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, trace.BadParameter("failed to append CA certificate")
		}
	}
	return &tls.Config{
		ServerName:   server.GetHostname(),
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}

// getConfigForClient returns TLS config with a list of certificate authorities
// that could have signed the client certificate.
func (s *ProxyServer) getConfigForClient(info *tls.ClientHelloInfo) (*tls.Config, error) {
	var clusterName string
	var err error
	if info.ServerName != "" {
		clusterName, err = auth.DecodeClusterName(info.ServerName)
		if err != nil && !trace.IsNotFound(err) {
			s.Debugf("Ignoring unsupported cluster name %q.", info.ServerName)
		}
	}
	pool, err := auth.ClientCertPool(s.AccessPoint, clusterName)
	if err != nil {
		s.WithError(err).Error("Failed to retrieve client CA pool.")
		return nil, nil // Fall back to the default config.
	}
	tlsCopy := s.TLSConfig.Clone()
	tlsCopy.ClientCAs = pool
	return tlsCopy, nil
}
