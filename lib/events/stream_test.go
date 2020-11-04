package events

import (
	"context"
	"testing"
	"time"

	"github.com/gravitational/teleport/lib/session"

	"github.com/stretchr/testify/assert"
)

// TestStreamerCompleteEmpty makes sure that streamer Complete function
// fails if streamer did gnot get a without getting a single event
func TestStreamerCompleteEmpty(t *testing.T) {
	uploader := NewMemoryUploader()

	streamer, err := NewProtoStreamer(ProtoStreamerConfig{
		Uploader: uploader,
	})
	assert.Nil(t, err)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	events := GenerateTestSession(SessionParams{PrintEvents: 1})
	sid := session.ID(events[0].(SessionMetadataGetter).GetSessionID())

	stream, err := streamer.CreateAuditStream(ctx, sid)
	assert.Nil(t, err)

	err = stream.Complete(ctx)
	assert.Nil(t, err)

	doneC := make(chan struct{})
	go func() {
		defer close(doneC)
		stream.Complete(ctx)
		stream.Close(ctx)
	}()

	select {
	case <-ctx.Done():
		t.Fatalf("Timeout waiting for emitter to complete")
	case <-doneC:
	}
}
