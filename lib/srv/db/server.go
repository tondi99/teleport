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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/labels"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
)

// TODO(r0mant): Redefined in srv/app/server.go.
type RotationGetter func(role teleport.Role) (*services.Rotation, error)

// Config is the configuration for an database proxy server.
type Config struct {
	// Clock used to control time.
	Clock clockwork.Clock

	// DataDir is the path to the data directory for the server.
	// TODO(r0mant): This is where sessions are stored?
	DataDir string

	// AuthClient is a client directly connected to the Auth server.
	AuthClient *auth.Client

	// AccessPoint is a caching client connected to the Auth Server.
	AccessPoint auth.AccessPoint

	// TLSConfig is the *tls.Config for this server.
	TLSConfig *tls.Config

	//
	TLSClientConfig *tls.Config

	// CipherSuites is the list of TLS cipher suites that have been configured
	// for this process.
	CipherSuites []uint16

	// Authorizer is used to authorize requests.
	Authorizer auth.Authorizer

	// GetRotation returns the certificate rotation state.
	GetRotation RotationGetter

	// Server contains the list of applications that will be proxied.
	Server services.Server

	// OnHeartbeat is called after every heartbeat. Used to update process state.
	OnHeartbeat func(error)
}

// CheckAndSetDefaults makes sure the configuration has the minimum required
// to function.
func (c *Config) CheckAndSetDefaults() error {
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	if c.DataDir == "" {
		return trace.BadParameter("data dir missing")
	}
	if c.AuthClient == nil {
		return trace.BadParameter("auth client log missing")
	}
	if c.AccessPoint == nil {
		return trace.BadParameter("access point missing")
	}
	if c.TLSConfig == nil {
		return trace.BadParameter("tls config missing")
	}
	if c.TLSClientConfig == nil {
		return trace.BadParameter("tls client config missing")
	}
	if len(c.CipherSuites) == 0 {
		return trace.BadParameter("cipersuites missing")
	}
	if c.Authorizer == nil {
		return trace.BadParameter("authorizer missing")
	}
	if c.GetRotation == nil {
		return trace.BadParameter("rotation getter missing")
	}
	if c.Server == nil {
		return trace.BadParameter("server missing")
	}
	if c.OnHeartbeat == nil {
		return trace.BadParameter("heartbeat missing")
	}
	return nil
}

// Server is an application server. It authenticates requests from the web
// proxy and forwards them to internal applications.
type Server struct {
	c   *Config
	log *logrus.Entry

	closeContext context.Context
	closeFunc    context.CancelFunc

	mu     sync.RWMutex
	server services.Server

	heartbeat     *srv.Heartbeat
	dynamicLabels map[string]*labels.Dynamic
}

// New returns a new application server.
func New(ctx context.Context, c *Config) (*Server, error) {
	err := c.CheckAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	s := &Server{
		c: c,
		log: logrus.WithFields(logrus.Fields{
			trace.Component: teleport.ComponentDB,
		}),
		server: c.Server,
	}

	s.c.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	s.c.TLSConfig.GetConfigForClient = s.getConfigForClient

	s.closeContext, s.closeFunc = context.WithCancel(ctx)

	// Create heartbeat loop so applications keep sending presence to backend.
	s.heartbeat, err = srv.NewHeartbeat(srv.HeartbeatConfig{
		Mode:            srv.HeartbeatModeDB,
		Context:         s.closeContext,
		Component:       teleport.ComponentDB,
		Announcer:       c.AccessPoint,
		GetServerInfo:   s.GetServerInfo,
		KeepAlivePeriod: defaults.ServerKeepAliveTTL,
		AnnouncePeriod:  defaults.ServerAnnounceTTL/2 + utils.RandomDuration(defaults.ServerAnnounceTTL/2),
		CheckPeriod:     defaults.HeartbeatCheckPeriod,
		ServerTTL:       defaults.ServerAnnounceTTL,
		OnHeartbeat:     c.OnHeartbeat,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return s, nil
}

// GetServerInfo returns a services.Server representing the database proxy.
func (s *Server) GetServerInfo() (services.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// // Update dynamic labels on all databases.
	// databases := s.server.GetDatabases()
	// for i := range databases {
	// 	labels, ok := s.dynamicLabels[a.Name]
	// 	if !ok {
	// 		continue
	// 	}
	// 	a.DynamicLabels = services.LabelsToV2(dl.Get())
	// }
	// s.server.SetApps(apps)

	// Update the TTL.
	s.server.SetTTL(s.c.Clock, defaults.ServerAnnounceTTL)

	// // Update rotation state.
	// rotation, err := s.c.GetRotation(teleport.RoleDatabase)
	// if err != nil {
	// 	if !trace.IsNotFound(err) {
	// 		s.log.Warningf("Failed to get rotation state: %v.", err)
	// 	}
	// } else {
	// 	s.server.SetRotation(*rotation)
	// }

	return s.server, nil
}

// Start starts heart beating the presence of service.Apps that this
// server is proxying along with any dynamic labels.
func (s *Server) Start() {
	// for _, dynamicLabel := range s.dynamicLabels {
	// 	go dynamicLabel.Start()
	// }
	go s.heartbeat.Run()
}

// Close will shut the server down and unblock any resources.
func (s *Server) Close() error {
	var errs []error

	// Stop heartbeat to auth.
	if err := s.heartbeat.Close(); err != nil {
		errs = append(errs, err)
	}

	// // Stop all dynamic labels from being updated.
	// for _, dynamicLabel := range s.dynamicLabels {
	// 	dynamicLabel.Close()
	// }

	// Signal to any blocking go routine that it should exit.
	s.closeFunc()

	return trace.NewAggregate(errs...)
}

// Wait will block while the server is running.
func (s *Server) Wait() error {
	<-s.closeContext.Done()
	return s.closeContext.Err()
}

// ForceHeartbeat is used in tests to force updating of services.Server.
func (s *Server) ForceHeartbeat() error {
	err := s.heartbeat.ForceSend(time.Second)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// HandleConnection ...
func (s *Server) HandleConnection(conn net.Conn) {
	s.log.Debugf("HandleConnection(%#v)", conn)
	//tlsConn := tls.Server(conn, s.c.TLSConfig)
	//if err := s.handleConnection(tlsConn); err != nil {
	if err := s.handleConnection(conn); err != nil {
		s.log.WithError(err).Error("Failed to handle connection")
	}
	return
	listener := newListener(context.TODO(), conn)
	tlsListener := tls.NewListener(listener, s.c.TLSConfig)
	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			s.log.WithError(err).Error("Failed to accept connection")
			continue
		}
		s.log.Debugf("Accepted connection from %v", conn.RemoteAddr())
		go func() {
			if err := s.handleConnection(conn); err != nil {
				s.log.WithError(err).Error("Failed to handle connection")
			}
		}()
	}
}

// sessionContext contains information about a database session.
type sessionContext struct {
	// id is the unique session id.
	id string
	// db is the database instance information.
	db *services.Database
	// dbUser is the requested database user.
	dbUser string
	// dbName is the requested database name.
	dbName string
}

func (s *Server) getConnectConfig(session sessionContext) (*pgconn.Config, error) {
	if session.db.Auth == "aws-iam" {
		return nil, nil
	}
	connString := fmt.Sprintf("postgres://%s@%s/?database=%s&sslmode=verify-ca",
		session.dbUser,
		session.db.Address,
		session.dbName)
	connectConfig, err := pgconn.ParseConfig(connString)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	addr, err := utils.ParseAddr(session.db.Address)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	connectConfig.TLSConfig, err = s.getClientTLSConfig(session.dbUser, addr.Host(), time.Hour)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connectConfig, nil
}

func (s *Server) handleConnection(conn net.Conn) error {
	backend := pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)

	s.log.Debug("Waiting for startup message")
	startupMessageI, err := backend.ReceiveStartupMessage()
	if err != nil {
		return trace.Wrap(err)
	}
	s.log.Debugf("Received startup message: %#v.", startupMessageI)

	startupMessage, ok := startupMessageI.(*pgproto3.StartupMessage)
	if !ok {
		return trace.BadParameter("expected *pgproto3.StartupMessage, got %T", startupMessageI)
	}

	// TODO(r0mant): Extract database from identity.
	database := s.server.GetDatabases()[0]
	s.log.Debugf("Will connect to database %#v", database)

	sessionCtx := sessionContext{
		id:     uuid.New(),
		db:     database,
		dbName: startupMessage.Parameters["database"],
		dbUser: startupMessage.Parameters["user"],
	}

	// caCertPool := x509.NewCertPool()
	// caCertBytes, err := base64.StdEncoding.DecodeString(database.CACert)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// certBytes, err := base64.StdEncoding.DecodeString(database.Cert)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// keyBytes, err := base64.StdEncoding.DecodeString(database.Key)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// if !caCertPool.AppendCertsFromPEM(caCertBytes) {
	// 	return trace.BadParameter("failed to append ca pem")
	// }
	// clientCert, err := tls.X509KeyPair(certBytes, keyBytes)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// connectConfig.TLSConfig = &tls.Config{
	// 	Certificates: []tls.Certificate{clientCert},
	// 	RootCAs:      caCertPool,
	// 	ServerName:   addr.Host(),
	// }
	// fmt.Printf("%#v", s.c.TLSClientConfig)
	// connectConfig.TLSConfig = s.c.TLSClientConfig
	// connectConfig.TLSConfig.ServerName = addr.Host()

	connectConfig, err := s.getConnectConfig(sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}

	// Connect to the backend database.
	frontendConn, err := pgconn.ConnectConfig(context.TODO(), connectConfig)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := s.emitSessionStartEvent(sessionCtx); err != nil {
		return trace.Wrap(err)
	}

	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(frontendConn.Conn()), frontendConn.Conn())

	s.log.Debug("Sending AuthenticationOk")
	if err := backend.Send(&pgproto3.AuthenticationOk{}); err != nil {
		return trace.Wrap(err)
	}
	s.log.Debug("Sent AuthenticationOk")

	s.log.Debug("Sending ReadyForQuery")
	if err := backend.Send(&pgproto3.ReadyForQuery{}); err != nil {
		return trace.Wrap(err)
	}
	s.log.Debug("Sent ReadyForQuery")

	go func() {
		log := s.log.WithField(trace.Component, "backend")
		defer log.Debug("Exited.")
		for {
			log.Debug("Receiving message")
			message, err := backend.Receive()
			if err != nil {
				log.WithError(err).Error("Failed to receive message from client")
				return
			}
			log.Debugf("Received message: %#v", message)
			switch msg := message.(type) {
			case *pgproto3.Query:
				log.Infof("---> Executing query %q", msg.String)
				if err := s.emitQueryEvent(sessionCtx, msg.String); err != nil {
					log.WithError(err).Error("Failed to emit audit event.")
				}
			case *pgproto3.Terminate:
				log.Infof("---> Session terminated")
				if err := s.emitSessionEndEvent(sessionCtx); err != nil {
					log.WithError(err).Error("Failed to emit audit event.")
				}
			}
			err = frontend.Send(message)
			if err != nil {
				log.WithError(err).Error("Failed to send message from client to server")
				return
			}
			log.Debug("Sent message")
		}
	}()

	log := s.log.WithField(trace.Component, "frontend")
	defer log.Debug("Exited.")
	for {
		log.Debug("Receiving message")
		message, err := frontend.Receive()
		if err != nil {
			log.WithError(err).Error("Failed to receive message from server")
			return trace.Wrap(err)
		}
		log.Debugf("Received message: %#v", message)
		switch msg := message.(type) {
		case *pgproto3.ErrorResponse:
			log.Warnf("<--- Query completed with error %q", msg.Message)
		case *pgproto3.DataRow:
			log.Infof("<--- Query returned data row with %v columns", len(msg.Values))
		case *pgproto3.CommandComplete:
			log.Infof("<--- Query completed")
		}
		err = backend.Send(message)
		if err != nil {
			log.WithError(err).Error("Failed to send message from server to client")
			return trace.Wrap(err)
		}
		log.Debug("Sent message")
	}

	// tlsConn, ok := conn.(*tls.Conn)
	// if !ok {
	// 	return trace.BadParameter("expected tls.Conn, got %T", conn)
	// }
	// err := tlsConn.Handshake()
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// s.log.Debugf("%#v", tlsConn.ConnectionState())
	return nil
}

func (s *Server) getClientTLSConfig(username, host string, ttl time.Duration) (*tls.Config, error) {
	s.log.Debug("Generating client certificate")
	privateBytes, publicBytes, err := native.GenerateKeyPair("")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// certs, err := s.c.AuthClient.GenerateUserCerts(context.TODO(), proto.UserCertsRequest{
	// 	PublicKey: publicBytes,
	// 	Username:  username,
	// 	Expires:   time.Now().UTC().Add(ttl),
	// })
	// if err != nil {
	// 	return nil, trace.Wrap(err)
	// }
	clusterName, err := s.c.AuthClient.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certAuthority, err := s.c.AuthClient.GetCertAuthority(services.CertAuthID{
		Type:       services.UserCA,
		DomainName: clusterName.GetClusterName(),
	}, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsAuthority, err := certAuthority.TLSCA()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cryptoPublicKey, err := sshutils.CryptoPublicKey(publicBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certBytes, err := tlsAuthority.GenerateCertificate(tlsca.CertificateRequest{
		PublicKey: cryptoPublicKey,
		Subject:   pkix.Name{CommonName: username},
		NotAfter:  time.Now().UTC().Add(ttl),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	clientCert, err := tls.X509KeyPair(certBytes, privateBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.log.Debugf("Generated client certificate: %#v", clientCert)
	caCertPool := x509.NewCertPool()
	for _, keypair := range certAuthority.GetTLSKeyPairs() {
		if !caCertPool.AppendCertsFromPEM(keypair.Cert) {
			return nil, trace.BadParameter("failed to append ca pem")
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   host,
	}, nil
}

// getConfigForClient returns TLS config with a list of certificate authorities
// that could have signed the client certificate.
//
// TODO(r0mant): Get rid of copy-pasta.
func (s *Server) getConfigForClient(info *tls.ClientHelloInfo) (*tls.Config, error) {
	var clusterName string
	var err error
	if info.ServerName != "" {
		clusterName, err = auth.DecodeClusterName(info.ServerName)
		if err != nil && !trace.IsNotFound(err) {
			s.log.Debugf("Ignoring unsupported cluster name %q.", info.ServerName)
		}
	}
	pool, err := auth.ClientCertPool(s.c.AccessPoint, clusterName)
	if err != nil {
		s.log.WithError(err).Error("Failed to retrieve client CA pool.")
		return nil, nil // Fall back to the default config.
	}
	tlsCopy := s.c.TLSConfig.Clone()
	tlsCopy.ClientCAs = pool
	return tlsCopy, nil
}
