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

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
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

// HandleConnection takes a connection and wraps it in a listener so it can
// be passed to http.Serve to process as a HTTP request.
func (s *Server) HandleConnection(conn net.Conn) {
	s.log.Infof("HandleConnection(%#v)", conn)
}
