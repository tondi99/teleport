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
	"path/filepath"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/events/filesessions"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/trace"
	"github.com/pborman/uuid"
)

// newStreamWriter creates a streamer that will be used to stream the
// requests that occur within this session to the audit log.
func (s *Server) newStreamWriter() (events.StreamWriter, error) {
	clusterConfig, err := s.c.AccessPoint.GetClusterConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Each chunk has it's own ID. Create a new UUID for this chunk which will be
	// emitted in a new event to the audit log that can be use to aggregate all
	// chunks for a particular session.
	chunkID := uuid.New()

	// Create a sync or async streamer depending on configuration of cluster.
	streamer, err := s.newStreamer(s.closeContext, chunkID, clusterConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	streamWriter, err := events.NewAuditWriter(events.AuditWriterConfig{
		// Audit stream is using server context, not session context,
		// to make sure that session is uploaded even after it is closed
		Context:      s.closeContext,
		Streamer:     streamer,
		Clock:        s.c.Clock,
		SessionID:    session.ID(chunkID),
		Namespace:    defaults.Namespace,
		ServerID:     s.c.Server.GetName(),
		RecordOutput: clusterConfig.GetSessionRecording() != services.RecordOff,
		Component:    teleport.ComponentApp,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return streamWriter, nil
}

// newStreamer returns sync or async streamer based on the configuration
// of the server and the session, sync streamer sends the events
// directly to the auth server and blocks if the events can not be received,
// async streamer buffers the events to disk and uploads the events later
func (s *Server) newStreamer(ctx context.Context, sessionID string, clusterConfig services.ClusterConfig) (events.Streamer, error) {
	mode := clusterConfig.GetSessionRecording()
	if services.IsRecordSync(mode) {
		s.log.Debugf("Using sync streamer for session %v.", sessionID)
		return s.c.AuthClient, nil
	}
	s.log.Debugf("Using async streamer for session %v.", sessionID)
	uploadDir := filepath.Join(
		s.c.DataDir, teleport.LogsDir, teleport.ComponentUpload,
		events.StreamingLogsDir, defaults.Namespace,
	)
	fileStreamer, err := filesessions.NewStreamer(uploadDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return fileStreamer, nil
}

func (s *Server) emitSessionStartEvent(session sessionContext) error {
	return s.c.AuthClient.EmitAuditEvent(s.closeContext, &events.DatabaseSessionStart{
		Metadata: events.Metadata{
			Type: events.DatabaseSessionStartEvent,
			Code: events.DatabaseSessionStartCode,
		},
		ServerMetadata: events.ServerMetadata{
			ServerID:        s.c.Server.GetName(),
			ServerNamespace: defaults.Namespace,
		},
		UserMetadata: events.UserMetadata{
			User: session.identity.Username,
		},
		SessionMetadata: events.SessionMetadata{
			SessionID: session.id,
		},
		DatabaseMetadata: &events.DatabaseMetadata{
			DBName:     session.db.Name,
			DBProtocol: session.db.Protocol,
			DBEndpoint: session.db.Endpoint,
			DBDatabase: session.dbName,
			DBUser:     session.dbUser,
		},
	})
}

func (s *Server) emitSessionEndEvent(session sessionContext) error {
	return s.c.AuthClient.EmitAuditEvent(s.closeContext, &events.DatabaseSessionEnd{
		Metadata: events.Metadata{
			Type: events.DatabaseSessionEndEvent,
			Code: events.DatabaseSessionEndCode,
		},
		UserMetadata: events.UserMetadata{
			User: session.identity.Username,
		},
		SessionMetadata: events.SessionMetadata{
			SessionID: session.id,
		},
		DatabaseMetadata: &events.DatabaseMetadata{
			DBName:     session.db.Name,
			DBProtocol: session.db.Protocol,
			DBEndpoint: session.db.Endpoint,
			DBDatabase: session.dbName,
			DBUser:     session.dbUser,
		},
	})
}

func (s *Server) emitQueryEvent(session sessionContext, query string) error {
	return s.c.AuthClient.EmitAuditEvent(s.closeContext, &events.DatabaseQuery{
		Metadata: events.Metadata{
			Type: events.DatabaseQueryEvent,
			Code: events.DatabaseQueryCode,
		},
		UserMetadata: events.UserMetadata{
			User: session.identity.Username,
		},
		SessionMetadata: events.SessionMetadata{
			SessionID: session.id,
		},
		DatabaseMetadata: &events.DatabaseMetadata{
			DBName:     session.db.Name,
			DBProtocol: session.db.Protocol,
			DBEndpoint: session.db.Endpoint,
			DBDatabase: session.dbName,
			DBUser:     session.dbUser,
		},
		Query: query,
	})
}
