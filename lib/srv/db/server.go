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
	"net"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/labels"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/gravitational/trace"
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

	// CipherSuites is the list of TLS cipher suites that have been configured
	// for this process.
	CipherSuites []uint16

	// Authorizer is used to authorize requests coming from proxy.
	Authorizer auth.Authorizer

	// GetRotation returns the certificate rotation state.
	GetRotation RotationGetter

	// Server contains the list of databaes that will be proxied.
	Server services.Server

	// Credentials are credentials to AWS API.
	//
	// Must have permissions to generate RDS auth tokens.
	Credentials *credentials.Credentials

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
	if c.Credentials == nil {
		// TODO(r0mant): Allow supplying credentials via yaml config.
		session, err := session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		// TODO(r0mant): Verify credentials have permission to generate RDS tokens.
		c.Credentials = session.Config.Credentials
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

	middleware auth.Middleware

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
		middleware: auth.Middleware{
			AccessPoint:   c.AccessPoint,
			AcceptedUsage: []string{teleport.UsageDatabaseOnly},
		},
	}

	s.c.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	s.c.TLSConfig.GetConfigForClient = getConfigForClient(s.c.TLSConfig, s.c.AccessPoint, s.log)

	s.closeContext, s.closeFunc = context.WithCancel(ctx)

	s.dynamicLabels = make(map[string]*labels.Dynamic)
	for _, db := range s.server.GetDatabases() {
		if len(db.DynamicLabels) == 0 {
			continue
		}
		dl, err := labels.NewDynamic(s.closeContext, &labels.DynamicConfig{
			Labels: services.V2ToLabels(db.DynamicLabels),
			Log:    s.log,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		dl.Sync()
		s.dynamicLabels[db.Name] = dl
	}

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

	// Update dynamic labels on all databases.
	databases := s.server.GetDatabases()
	for _, db := range databases {
		labels, ok := s.dynamicLabels[db.Name]
		if !ok {
			continue
		}
		db.DynamicLabels = services.LabelsToV2(labels.Get())
	}
	s.server.SetDatabases(databases)

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

// Start starts heartbeating the presence of service.Databases that this
// server is proxying along with any dynamic labels.
func (s *Server) Start() {
	for _, dynamicLabel := range s.dynamicLabels {
		go dynamicLabel.Start()
	}
	go s.heartbeat.Run()
}

// Close will shut the server down and unblock any resources.
func (s *Server) Close() error {
	var errs []error

	// Stop heartbeat to auth.
	if err := s.heartbeat.Close(); err != nil {
		errs = append(errs, err)
	}

	// Stop all dynamic labels from being updated.
	for _, dynamicLabel := range s.dynamicLabels {
		dynamicLabel.Close()
	}

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
	s.log.Debugf("Accepted connection from %v.", conn.RemoteAddr())
	// Upgrade the connection to TLS since the other side of the reverse
	// tunnel connection (proxy) will initiate a handshake.
	tlsConn := tls.Server(conn, s.c.TLSConfig)
	// Perform the hanshake explicitly, normally it should be performed
	// on the first read/write but when the connection is passed over
	// reverse tunnel it doesn't happen for some reason.
	err := tlsConn.Handshake()
	if err != nil {
		s.log.WithError(err).Error("Failed to perform TLS handshake.")
		return
	}
	// Now that handshake has completed and the client has sent us a
	// certificate, extract identity information from it.
	ctx, err := s.middleware.WrapContext(context.TODO(), tlsConn)
	if err != nil {
		s.log.WithError(err).Error("Failed to extract identity from connection.")
		return
	}
	// Dispatch the connection for processing by an appropriate database
	// service.
	err = s.handleConnection(ctx, tlsConn)
	if err != nil {
		s.log.WithError(err).Error("Failed to handle connection.")
		return
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) error {
	sessionCtx, err := s.authorize(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	engine := &postgresEngine{
		authClient:     s.c.AuthClient,
		credentials:    s.c.Credentials,
		onSessionStart: s.emitSessionStartEvent,
		onSessionEnd:   s.emitSessionEndEvent,
		onQuery:        s.emitQueryEvent,
		clock:          s.c.Clock,
		FieldLogger:    s.log,
	}
	err = engine.handleConnection(ctx, sessionCtx, conn)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (s *Server) authorize(ctx context.Context) (*sessionContext, error) {
	// Only allow local and remote identities to proxy to a database.
	userType := ctx.Value(auth.ContextUser)
	switch userType.(type) {
	case auth.LocalUser, auth.RemoteUser:
	default:
		return nil, trace.BadParameter("invalid identity: %T", userType)
	}
	// Extract authorizing context and identity of the user from the request.
	authContext, err := s.c.Authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	identity := authContext.Identity.GetIdentity()
	// Fetch the requested database.
	var db *services.Database
	for _, d := range s.server.GetDatabases() {
		if d.Name == identity.RouteToDatabase.DatabaseName {
			db = d
		}
	}
	s.log.Debugf("Will connect to database %q/%v.", db.Name, db.Endpoint)
	err = authContext.Checker.CheckAccessToDatabase(defaults.Namespace, db)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &sessionContext{
		id:       uuid.New(),
		db:       db,
		identity: identity,
	}, nil
}
