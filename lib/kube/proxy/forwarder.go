/*
Copyright 2018-2020 Gravitational, Inc.

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

package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/events/filesessions"
	"github.com/gravitational/teleport/lib/httplib"
	kubeutils "github.com/gravitational/teleport/lib/kube/utils"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/oxy/forward"
	"github.com/gravitational/trace"
	"github.com/gravitational/ttlmap"
	"github.com/jonboulle/clockwork"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"
	utilexec "k8s.io/client-go/util/exec"
)

// ForwarderConfig specifies configuration for proxy forwarder
type ForwarderConfig struct {
	// Tunnel is the teleport reverse tunnel server
	Tunnel reversetunnel.Server
	// ClusterName is a local cluster name
	ClusterName string
	// Keygen points to a key generator implementation
	Keygen sshca.Authority
	// Auth authenticates user
	Auth auth.Authorizer
	// Client is a proxy client
	Client auth.ClientI
	// DataDir is a data dir to store logs
	DataDir string
	// Namespace is a namespace of the proxy server (not a K8s namespace)
	Namespace string
	// AccessPoint is a caching access point to auth server
	// for caching common requests to the backend
	AccessPoint auth.AccessPoint
	// ServerID is a unique ID of a proxy server
	ServerID string
	// ClusterOverride if set, routes all requests
	// to the cluster name, used in tests
	ClusterOverride string
	// Context passes the optional external context
	// passing global close to all forwarder operations
	Context context.Context
	// KubeconfigPath is a path to kubernetes configuration
	KubeconfigPath string
	// NewKubeService specifies whether to apply the additional kubernetes_service features:
	// - parsing multiple kubeconfig entries
	// - enforcing self permission check
	NewKubeService bool
	// KubeClusterName is the name of the kubernetes cluster that this
	// forwarder handles.
	KubeClusterName string
	// Clock is a server clock, could be overridden in tests
	Clock clockwork.Clock
	// PingPeriod is a period for sending ping messages on the incoming
	// connection.
	PingPeriod time.Duration
	// Component name to include in log output.
	Component string
}

// CheckAndSetDefaults checks and sets default values
func (f *ForwarderConfig) CheckAndSetDefaults() error {
	if f.Client == nil {
		return trace.BadParameter("missing parameter Client")
	}
	if f.AccessPoint == nil {
		return trace.BadParameter("missing parameter AccessPoint")
	}
	if f.Auth == nil {
		return trace.BadParameter("missing parameter Auth")
	}
	if f.ClusterName == "" {
		return trace.BadParameter("missing parameter LocalCluster")
	}
	if f.Keygen == nil {
		return trace.BadParameter("missing parameter Keygen")
	}
	if f.DataDir == "" {
		return trace.BadParameter("missing parameter DataDir")
	}
	if f.ServerID == "" {
		return trace.BadParameter("missing parameter ServerID")
	}
	if f.Namespace == "" {
		f.Namespace = defaults.Namespace
	}
	if f.Context == nil {
		f.Context = context.TODO()
	}
	if f.Clock == nil {
		f.Clock = clockwork.NewRealClock()
	}
	if f.PingPeriod == 0 {
		f.PingPeriod = defaults.HighResPollingPeriod
	}
	if f.Component == "" {
		f.Component = "kube_forwarder"
	}
	if f.KubeClusterName == "" && f.KubeconfigPath == "" {
		// Running without a kubeconfig and explicit k8s cluster name. Use
		// teleport cluster name instead, to ask kubeutils.GetKubeConfig to
		// attempt loading the in-cluster credentials.
		f.KubeClusterName = f.ClusterName
	}
	return nil
}

// NewForwarder returns new instance of Kubernetes request
// forwarding proxy.
func NewForwarder(cfg ForwarderConfig) (*Forwarder, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	log := log.WithFields(log.Fields{
		trace.Component: cfg.Component,
	})

	creds, err := getKubeCreds(cfg.Context, log, cfg.ClusterName, cfg.KubeClusterName, cfg.KubeconfigPath, cfg.NewKubeService)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clusterSessions, err := ttlmap.New(defaults.ClientCacheSize)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	closeCtx, close := context.WithCancel(cfg.Context)
	fwd := &Forwarder{
		creds:           creds,
		Entry:           log,
		Router:          *httprouter.New(),
		ForwarderConfig: cfg,
		clusterSessions: clusterSessions,
		activeRequests:  make(map[string]context.Context),
		ctx:             closeCtx,
		close:           close,
	}

	fwd.POST("/api/:ver/namespaces/:podNamespace/pods/:podName/exec", fwd.withAuth(fwd.exec))
	fwd.GET("/api/:ver/namespaces/:podNamespace/pods/:podName/exec", fwd.withAuth(fwd.exec))

	fwd.POST("/api/:ver/namespaces/:podNamespace/pods/:podName/attach", fwd.withAuth(fwd.exec))
	fwd.GET("/api/:ver/namespaces/:podNamespace/pods/:podName/attach", fwd.withAuth(fwd.exec))

	fwd.POST("/api/:ver/namespaces/:podNamespace/pods/:podName/portforward", fwd.withAuth(fwd.portForward))
	fwd.GET("/api/:ver/namespaces/:podNamespace/pods/:podName/portforward", fwd.withAuth(fwd.portForward))

	fwd.NotFound = fwd.withAuthStd(fwd.catchAll)

	if cfg.ClusterOverride != "" {
		fwd.Debugf("Cluster override is set, forwarder will send all requests to remote cluster %v.", cfg.ClusterOverride)
	}
	return fwd, nil
}

// Forwarder intercepts kubernetes requests, acting as Kubernetes API proxy.
// it blindly forwards most of the requests on HTTPS protocol layer,
// however some requests like exec sessions it intercepts and records.
type Forwarder struct {
	sync.Mutex
	*log.Entry
	httprouter.Router
	ForwarderConfig
	// clusterSessions is an expiring cache associated with authenticated
	// user connected to a remote cluster, session is invalidated
	// if user changes kubernetes groups via RBAC or cache has expired
	// TODO(klizhentas): flush certs on teleport CA rotation?
	clusterSessions *ttlmap.TTLMap
	// activeRequests is a map used to serialize active CSR requests to the auth server
	activeRequests map[string]context.Context
	// close is a close function
	close context.CancelFunc
	// ctx is a global context signalling exit
	ctx context.Context
	// creds contain kubernetes credentials for multiple clusters.
	// map key is cluster name.
	creds map[string]*kubeCreds
}

// Close signals close to all outstanding or background operations
// to complete
func (f *Forwarder) Close() error {
	f.close()
	return nil
}

// authContext is a context of authenticated user,
// contains information about user, target cluster and authenticated groups
type authContext struct {
	auth.Context
	kubeGroups      map[string]struct{}
	kubeUsers       map[string]struct{}
	kubeCluster     string
	teleportCluster teleportClusterClient
	clusterConfig   services.ClusterConfig
	// clientIdleTimeout sets information on client idle timeout
	clientIdleTimeout time.Duration
	// disconnectExpiredCert if set, controls the time when the connection
	// should be disconnected because the client cert expires
	disconnectExpiredCert time.Time
	// sessionTTL specifies the duration of the user's session
	sessionTTL time.Duration
}

func (c authContext) String() string {
	return fmt.Sprintf("user: %v, users: %v, groups: %v, teleport cluster: %v, kube cluster: %v", c.User.GetName(), c.kubeUsers, c.kubeGroups, c.teleportCluster.name, c.kubeCluster)
}

func (c *authContext) key() string {
	// it is important that the context key contains user, kubernetes groups and certificate expiry,
	// so that new logins with different parameters will not reuse this context
	return fmt.Sprintf("%v:%v:%v:%v:%v:%v", c.teleportCluster.name, c.User.GetName(), c.kubeUsers, c.kubeGroups, c.kubeCluster, c.disconnectExpiredCert.UTC().Unix())
}

type dialFunc func(ctx context.Context, network, addr, serverID string) (net.Conn, error)

// teleportClusterClient is a client for either a k8s endpoint in local cluster or a
// proxy endpoint in a remote cluster.
type teleportClusterClient struct {
	remoteAddr utils.NetAddr
	name       string
	dial       dialFunc
	// targetAddr is a direct network address.
	targetAddr string
	//serverID is an address reachable over a reverse tunnel.
	serverID       string
	isRemote       bool
	isRemoteClosed func() bool
}

func (c *teleportClusterClient) Dial(network, addr string) (net.Conn, error) {
	return c.DialWithContext(context.Background(), network, addr)
}

func (c *teleportClusterClient) DialWithContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.dial(ctx, network, c.targetAddr, c.serverID)
}

// handlerWithAuthFunc is http handler with passed auth context
type handlerWithAuthFunc func(ctx *authContext, w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error)

// handlerWithAuthFuncStd is http handler with passed auth context
type handlerWithAuthFuncStd func(ctx *authContext, w http.ResponseWriter, r *http.Request) (interface{}, error)

// authenticate function authenticates request
func (f *Forwarder) authenticate(req *http.Request) (*authContext, error) {
	const accessDeniedMsg = "[00] access denied"

	var isRemoteUser bool
	userTypeI := req.Context().Value(auth.ContextUser)
	switch userTypeI.(type) {
	case auth.LocalUser:

	case auth.RemoteUser:
		isRemoteUser = true
	case auth.BuiltinRole:
		f.Warningf("Denying proxy access to unauthenticated user of type %T - this can sometimes be caused by inadvertently using an HTTP load balancer instead of a TCP load balancer on the Kubernetes port.", userTypeI)
		return nil, trace.AccessDenied(accessDeniedMsg)
	default:
		f.Warningf("Denying proxy access to unsupported user type: %T.", userTypeI)
		return nil, trace.AccessDenied(accessDeniedMsg)
	}

	userContext, err := f.Auth.Authorize(req.Context())
	if err != nil {
		switch {
		// propagate connection problem error so we can differentiate
		// between connection failed and access denied
		case trace.IsConnectionProblem(err):
			return nil, trace.ConnectionProblem(err, "[07] failed to connect to the database")
		case trace.IsAccessDenied(err):
			// don't print stack trace, just log the warning
			f.Warn(err)
			return nil, trace.AccessDenied(accessDeniedMsg)
		default:
			f.Warn(trace.DebugReport(err))
			return nil, trace.AccessDenied(accessDeniedMsg)
		}
	}
	peers := req.TLS.PeerCertificates
	if len(peers) > 1 {
		// when turning intermediaries on, don't forget to verify
		// https://github.com/kubernetes/kubernetes/pull/34524/files#diff-2b283dde198c92424df5355f39544aa4R59
		return nil, trace.AccessDenied("access denied: intermediaries are not supported")
	}
	if len(peers) == 0 {
		return nil, trace.AccessDenied("access denied: only mutual TLS authentication is supported")
	}
	clientCert := peers[0]
	authContext, err := f.setupContext(*userContext, req, isRemoteUser, clientCert.NotAfter)
	if err != nil {
		f.Warn(err.Error())
		return nil, trace.AccessDenied(accessDeniedMsg)
	}
	return authContext, nil
}

func (f *Forwarder) withAuthStd(handler handlerWithAuthFuncStd) http.HandlerFunc {
	return httplib.MakeStdHandler(func(w http.ResponseWriter, req *http.Request) (interface{}, error) {
		authContext, err := f.authenticate(req)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return handler(authContext, w, req)
	})
}

func (f *Forwarder) withAuth(handler handlerWithAuthFunc) httprouter.Handle {
	return httplib.MakeHandler(func(w http.ResponseWriter, req *http.Request, p httprouter.Params) (interface{}, error) {
		authContext, err := f.authenticate(req)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return handler(authContext, w, req, p)
	})
}

func (f *Forwarder) setupContext(ctx auth.Context, req *http.Request, isRemoteUser bool, certExpires time.Time) (*authContext, error) {
	roles := ctx.Checker

	clusterConfig, err := f.AccessPoint.GetClusterConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// adjust session ttl to the smaller of two values: the session
	// ttl requested in tsh or the session ttl for the role.
	sessionTTL := roles.AdjustSessionTTL(time.Hour)

	// check signing TTL and return a list of allowed logins
	kubeGroups, kubeUsers, err := roles.CheckKubeGroupsAndUsers(sessionTTL, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// By default, if no kubernetes_users is set (which will be a majority),
	// user will impersonate themselves, which is the backwards-compatible behavior.
	if len(kubeUsers) == 0 {
		kubeUsers = append(kubeUsers, ctx.User.GetName())
	}

	// KubeSystemAuthenticated is a builtin group that allows
	// any user to access common API methods, e.g. discovery methods
	// required for initial client usage, without it, restricted user's
	// kubectl clients will not work
	if !utils.SliceContainsStr(kubeGroups, teleport.KubeSystemAuthenticated) {
		kubeGroups = append(kubeGroups, teleport.KubeSystemAuthenticated)
	}

	identity := ctx.Identity.GetIdentity()
	teleportClusterName := identity.RouteToCluster
	if teleportClusterName == "" {
		teleportClusterName = f.ClusterName
	}
	isRemoteCluster := f.ClusterName != teleportClusterName

	if isRemoteCluster && isRemoteUser {
		return nil, trace.AccessDenied("access denied: remote user can not access remote cluster")
	}

	// Get a dialer for either a k8s endpoint in current cluster or a tunneled
	// endpoint for a leaf teleport cluster.
	var dialFn dialFunc
	var isRemoteClosed func() bool
	if isRemoteCluster {
		// Tunnel is nil for a teleport process with "kubernetes_service" but
		// not "proxy_service".
		if f.Tunnel == nil {
			return nil, trace.BadParameter("this Teleport process can not dial Kubernetes endpoints in remote Teleport clusters; only proxy_service supports this, make sure a Teleport proxy is first in the request path")
		}

		targetCluster, err := f.Tunnel.GetSite(teleportClusterName)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		dialFn = func(ctx context.Context, network, addr, serverID string) (net.Conn, error) {
			return targetCluster.DialTCP(reversetunnel.DialParams{
				From:     &utils.NetAddr{AddrNetwork: "tcp", Addr: req.RemoteAddr},
				To:       &utils.NetAddr{AddrNetwork: "tcp", Addr: addr},
				ConnType: services.KubeTunnel,
				ServerID: serverID,
			})
		}
		isRemoteClosed = targetCluster.IsClosed
	} else if f.Tunnel != nil {
		// Not a remote cluster and we have a reverse tunnel server.
		// Use the local reversetunnel.Site which knows how to dial by serverID
		// (for "kubernetes_service" connected over a tunnel) and falls back to
		// direct dial if needed.
		localCluster, err := f.Tunnel.GetSite(f.ClusterName)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		dialFn = func(ctx context.Context, network, addr, serverID string) (net.Conn, error) {
			return localCluster.DialTCP(reversetunnel.DialParams{
				From:     &utils.NetAddr{AddrNetwork: "tcp", Addr: req.RemoteAddr},
				To:       &utils.NetAddr{AddrNetwork: "tcp", Addr: addr},
				ConnType: services.KubeTunnel,
				ServerID: serverID,
			})
		}
		isRemoteClosed = localCluster.IsClosed
	} else {
		// Don't have a reverse tunnel server, so we can only dial directly.
		dialFn = func(ctx context.Context, network, addr, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, addr)
		}
		isRemoteClosed = func() bool { return false }
	}

	authCtx := &authContext{
		clientIdleTimeout: roles.AdjustClientIdleTimeout(clusterConfig.GetClientIdleTimeout()),
		sessionTTL:        sessionTTL,
		Context:           ctx,
		kubeGroups:        utils.StringsSet(kubeGroups),
		kubeUsers:         utils.StringsSet(kubeUsers),
		clusterConfig:     clusterConfig,
		teleportCluster: teleportClusterClient{
			name:           teleportClusterName,
			remoteAddr:     utils.NetAddr{AddrNetwork: "tcp", Addr: req.RemoteAddr},
			dial:           dialFn,
			isRemote:       isRemoteCluster,
			isRemoteClosed: isRemoteClosed,
		},
	}

	authCtx.kubeCluster = identity.KubernetesCluster
	if !isRemoteCluster {
		kubeCluster, err := kubeutils.CheckOrSetKubeCluster(req.Context(), f.AccessPoint, identity.KubernetesCluster, teleportClusterName)
		if err != nil {
			if !trace.IsNotFound(err) {
				return nil, trace.Wrap(err)
			}
			// Fallback for old clusters and old user certs. Assume that the
			// user is trying to access the default cluster name.
			kubeCluster = teleportClusterName
		}
		authCtx.kubeCluster = kubeCluster
	}

	disconnectExpiredCert := roles.AdjustDisconnectExpiredCert(clusterConfig.GetDisconnectExpiredCert())
	if !certExpires.IsZero() && disconnectExpiredCert {
		authCtx.disconnectExpiredCert = certExpires
	}

	return authCtx, nil
}

// newStreamer returns sync or async streamer based on the configuration
// of the server and the session, sync streamer sends the events
// directly to the auth server and blocks if the events can not be received,
// async streamer buffers the events to disk and uploads the events later
func (f *Forwarder) newStreamer(ctx *authContext) (events.Streamer, error) {
	mode := ctx.clusterConfig.GetSessionRecording()
	if services.IsRecordSync(mode) {
		f.Debugf("Using sync streamer for session")
		return f.Client, nil
	}
	f.Debugf("Using async streamer for session.")
	dir := filepath.Join(
		f.DataDir, teleport.LogsDir, teleport.ComponentUpload,
		events.StreamingLogsDir, defaults.Namespace,
	)
	fileStreamer, err := filesessions.NewStreamer(dir)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// TeeStreamer sends non-print and non disk events
	// to the audit log in async mode, while buffering all
	// events on disk for further upload at the end of the session
	return events.NewTeeStreamer(fileStreamer, f.Client), nil
}

// exec forwards all exec requests to the target server, captures
// all output from the session
func (f *Forwarder) exec(ctx *authContext, w http.ResponseWriter, req *http.Request, p httprouter.Params) (interface{}, error) {
	f.Debugf("Exec %v.", req.URL.String())
	q := req.URL.Query()
	request := remoteCommandRequest{
		podNamespace:       p.ByName("podNamespace"),
		podName:            p.ByName("podName"),
		containerName:      q.Get("container"),
		cmd:                q["command"],
		stdin:              utils.AsBool(q.Get("stdin")),
		stdout:             utils.AsBool(q.Get("stdout")),
		stderr:             utils.AsBool(q.Get("stderr")),
		tty:                utils.AsBool(q.Get("tty")),
		httpRequest:        req,
		httpResponseWriter: w,
		context:            req.Context(),
		pingPeriod:         f.PingPeriod,
	}

	var recorder events.SessionRecorder
	var emitter events.Emitter
	sessionID := session.NewID()
	var err error
	if f.NewKubeService {
		// Proxy should be recording all the events, so we don't have to.
		emitter = events.NewDiscardEmitter()
		request.onResize = func(resize remotecommand.TerminalSize) {}
	} else if request.tty {
		streamer, err := f.newStreamer(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		// create session recorder
		// get the audit log from the server and create a session recorder. this will
		// be a discard audit log if the proxy is in recording mode and a teleport
		// node so we don't create double recordings.
		recorder, err = events.NewAuditWriter(events.AuditWriterConfig{
			// Audit stream is using server context, not session context,
			// to make sure that session is uploaded even after it is closed
			Context:      f.Context,
			Streamer:     streamer,
			Clock:        f.Clock,
			SessionID:    sessionID,
			ServerID:     f.ServerID,
			Namespace:    f.Namespace,
			RecordOutput: ctx.clusterConfig.GetSessionRecording() != services.RecordOff,
			Component:    teleport.Component(teleport.ComponentSession, teleport.ComponentProxyKube),
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		emitter = recorder
		defer recorder.Close(f.Context)
		request.onResize = func(resize remotecommand.TerminalSize) {
			params := session.TerminalParams{
				W: int(resize.Width),
				H: int(resize.Height),
			}
			// Build the resize event.
			resizeEvent := &events.Resize{
				Metadata: events.Metadata{
					Type: events.ResizeEvent,
					Code: events.TerminalResizeCode,
				},
				ConnectionMetadata: events.ConnectionMetadata{
					RemoteAddr: req.RemoteAddr,
					Protocol:   events.EventProtocolKube,
				},
				ServerMetadata: events.ServerMetadata{
					ServerNamespace: f.Namespace,
				},
				SessionMetadata: events.SessionMetadata{
					SessionID: string(sessionID),
				},
				UserMetadata: events.UserMetadata{
					User:  ctx.User.GetName(),
					Login: ctx.User.GetName(),
				},
				TerminalSize: params.Serialize(),
			}

			// Report the updated window size to the event log (this is so the sessions
			// can be replayed correctly).
			if err := recorder.EmitAuditEvent(f.Context, resizeEvent); err != nil {
				f.WithError(err).Warn("Failed to emit terminal resize event.")
			}
		}
	} else {
		emitter = f.Client
	}

	sess, err := f.getOrCreateClusterSession(*ctx)
	if err != nil {
		// This error goes to kubernetes client and is not visible in the logs
		// of the teleport server if not logged here.
		f.Errorf("Failed to create cluster session: %v.", err)
		return nil, trace.Wrap(err)
	}
	sessionStart := f.Clock.Now().UTC()

	if request.tty {
		// Emit "new session created" event. There are no initial terminal
		// parameters per k8s protocol, so set up with any default
		termParams := session.TerminalParams{
			W: 100,
			H: 100,
		}
		sessionStartEvent := &events.SessionStart{
			Metadata: events.Metadata{
				Type: events.SessionStartEvent,
				Code: events.SessionStartCode,
			},
			ServerMetadata: events.ServerMetadata{
				ServerID:        f.ServerID,
				ServerNamespace: f.Namespace,
				ServerHostname:  sess.teleportCluster.name,
				ServerAddr:      sess.teleportCluster.targetAddr,
			},
			SessionMetadata: events.SessionMetadata{
				SessionID: string(sessionID),
			},
			UserMetadata: events.UserMetadata{
				User:  ctx.User.GetName(),
				Login: ctx.User.GetName(),
			},
			ConnectionMetadata: events.ConnectionMetadata{
				RemoteAddr: req.RemoteAddr,
				LocalAddr:  sess.teleportCluster.targetAddr,
				Protocol:   events.EventProtocolKube,
			},
			TerminalSize: termParams.Serialize(),
		}
		if err := emitter.EmitAuditEvent(f.Context, sessionStartEvent); err != nil {
			f.WithError(err).Warn("Failed to emit event.")
		}
	}

	if err := f.setupForwardingHeaders(sess, req); err != nil {
		return nil, trace.Wrap(err)
	}

	proxy, err := createRemoteCommandProxy(request)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer proxy.Close()

	f.Debugf("Created streams, getting executor.")

	executor, err := f.getExecutor(*ctx, sess, req)
	if err != nil {
		f.WithError(err).Warning("Failed creating executor.")
		return nil, trace.Wrap(err)
	}
	streamOptions := proxy.options()

	if recorder != nil {
		// capture stderr and stdout writes to session recorder
		streamOptions.Stdout = utils.NewBroadcastWriter(streamOptions.Stdout, recorder)
		streamOptions.Stderr = utils.NewBroadcastWriter(streamOptions.Stderr, recorder)
	}

	if err = executor.Stream(streamOptions); err != nil {
		f.WithError(err).Warning("Executor failed while streaming.")
		return nil, trace.Wrap(err)
	}
	if err := proxy.sendStatus(err); err != nil {
		f.WithError(err).Warning("Failed to send status. Exec command was aborted by client.")
		return nil, trace.Wrap(err)
	}

	if request.tty {
		sessionEndEvent := &events.SessionEnd{
			Metadata: events.Metadata{
				Type: events.SessionEndEvent,
				Code: events.SessionEndCode,
			},
			ServerMetadata: events.ServerMetadata{
				ServerID:        f.ServerID,
				ServerNamespace: f.Namespace,
			},
			SessionMetadata: events.SessionMetadata{
				SessionID: string(sessionID),
			},
			UserMetadata: events.UserMetadata{
				User:  ctx.User.GetName(),
				Login: ctx.User.GetName(),
			},
			ConnectionMetadata: events.ConnectionMetadata{
				RemoteAddr: req.RemoteAddr,
				LocalAddr:  sess.teleportCluster.targetAddr,
				Protocol:   events.EventProtocolKube,
			},
			Interactive: true,
			// There can only be 1 participant, k8s sessions are not join-able.
			Participants: []string{ctx.User.GetName()},
			StartTime:    sessionStart,
			EndTime:      f.Clock.Now().UTC(),
		}
		if err := emitter.EmitAuditEvent(f.Context, sessionEndEvent); err != nil {
			f.WithError(err).Warn("Failed to emit session end event.")
		}
	} else {
		// send an exec event
		execEvent := &events.Exec{
			Metadata: events.Metadata{
				Type: events.ExecEvent,
			},
			ServerMetadata: events.ServerMetadata{
				ServerID:        f.ServerID,
				ServerNamespace: f.Namespace,
			},
			SessionMetadata: events.SessionMetadata{
				SessionID: string(sessionID),
			},
			UserMetadata: events.UserMetadata{
				User:  ctx.User.GetName(),
				Login: ctx.User.GetName(),
			},
			ConnectionMetadata: events.ConnectionMetadata{
				RemoteAddr: req.RemoteAddr,
				LocalAddr:  sess.teleportCluster.targetAddr,
				Protocol:   events.EventProtocolKube,
			},
			CommandMetadata: events.CommandMetadata{
				Command: strings.Join(request.cmd, " "),
			},
		}
		if err != nil {
			execEvent.Code = events.ExecFailureCode
			execEvent.Error = err.Error()
			if exitErr, ok := err.(utilexec.ExitError); ok && exitErr.Exited() {
				execEvent.ExitCode = fmt.Sprintf("%d", exitErr.ExitStatus())
			}
		} else {
			execEvent.Code = events.ExecCode
		}
		if err := emitter.EmitAuditEvent(f.Context, execEvent); err != nil {
			f.WithError(err).Warn("Failed to emit event.")
		}
	}

	f.Debugf("Exited successfully.")
	return nil, nil
}

// portForward starts port forwarding to the remote cluster
func (f *Forwarder) portForward(ctx *authContext, w http.ResponseWriter, req *http.Request, p httprouter.Params) (interface{}, error) {
	f.Debugf("Port forward: %v. req headers: %v", req.URL.String(), req.Header)
	sess, err := f.getOrCreateClusterSession(*ctx)
	if err != nil {
		// This error goes to kubernetes client and is not visible in the logs
		// of the teleport server if not logged here.
		f.Errorf("Failed to create cluster session: %v.", err)
		return nil, trace.Wrap(err)
	}

	if err := f.setupForwardingHeaders(sess, req); err != nil {
		f.Debugf("DENIED Port forward: %v.", req.URL.String())
		return nil, trace.Wrap(err)
	}

	dialer, err := f.getDialer(*ctx, sess, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	onPortForward := func(addr string, success bool) {
		if f.NewKubeService {
			// Proxy should be recording all the events, so we don't have to.
			return
		}
		portForward := &events.PortForward{
			Metadata: events.Metadata{
				Type: events.PortForwardEvent,
				Code: events.PortForwardCode,
			},
			UserMetadata: events.UserMetadata{
				Login: ctx.User.GetName(),
				User:  ctx.User.GetName(),
			},
			ConnectionMetadata: events.ConnectionMetadata{
				LocalAddr:  sess.teleportCluster.targetAddr,
				RemoteAddr: req.RemoteAddr,
				Protocol:   events.EventProtocolKube,
			},
			Addr: addr,
			Status: events.Status{
				Success: success,
			},
		}
		if !success {
			portForward.Code = events.PortForwardFailureCode
		}
		if err := f.Client.EmitAuditEvent(f.Context, portForward); err != nil {
			f.WithError(err).Warn("Failed to emit event.")
		}
	}

	q := req.URL.Query()
	request := portForwardRequest{
		podNamespace:       p.ByName("podNamespace"),
		podName:            p.ByName("podName"),
		ports:              q["ports"],
		context:            req.Context(),
		httpRequest:        req,
		httpResponseWriter: w,
		onPortForward:      onPortForward,
		targetDialer:       dialer,
		pingPeriod:         f.PingPeriod,
	}
	f.Debugf("Starting %v.", request)
	err = runPortForwarding(request)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	f.Debugf("Done %v.", request)
	return nil, nil
}

const (
	// ImpersonateHeaderPrefix is K8s impersonation prefix for impersonation feature:
	// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation
	ImpersonateHeaderPrefix = "Impersonate-"
	// ImpersonateUserHeader is impersonation header for users
	ImpersonateUserHeader = "Impersonate-User"
	// ImpersonateGroupHeader is K8s impersonation header for user
	ImpersonateGroupHeader = "Impersonate-Group"
	// ImpersonationRequestDeniedMessage is access denied message for impersonation
	ImpersonationRequestDeniedMessage = "impersonation request has been denied"
)

func (f *Forwarder) setupForwardingHeaders(sess *clusterSession, req *http.Request) error {
	if err := setupImpersonationHeaders(f.Entry, sess.authContext, req.Header); err != nil {
		return trace.Wrap(err)
	}

	// Setup scheme, override target URL to the destination address
	req.URL.Scheme = "https"
	req.URL.Host = sess.teleportCluster.targetAddr
	req.RequestURI = req.URL.Path + "?" + req.URL.RawQuery

	// add origin headers so the service consuming the request on the other site
	// is aware of where it came from
	req.Header.Add("X-Forwarded-Proto", "https")
	req.Header.Add("X-Forwarded-Host", req.Host)
	req.Header.Add("X-Forwarded-Path", req.URL.Path)
	req.Header.Add("X-Forwarded-For", req.RemoteAddr)

	return nil
}

// setupImpersonationHeaders sets up Impersonate-User and Impersonate-Group headers
func setupImpersonationHeaders(log log.FieldLogger, ctx authContext, headers http.Header) error {
	var impersonateUser string
	var impersonateGroups []string
	for header, values := range headers {
		if !strings.HasPrefix(header, "Impersonate-") {
			continue
		}
		switch header {
		case ImpersonateUserHeader:
			if impersonateUser != "" {
				return trace.AccessDenied("%v, user already specified to %q", ImpersonationRequestDeniedMessage, impersonateUser)
			}
			if len(values) == 0 || len(values) > 1 {
				return trace.AccessDenied("%v, invalid user header %q", ImpersonationRequestDeniedMessage, values)
			}
			impersonateUser = values[0]
			if _, ok := ctx.kubeUsers[impersonateUser]; !ok {
				return trace.AccessDenied("%v, user header %q is not allowed in roles", ImpersonationRequestDeniedMessage, impersonateUser)
			}
		case ImpersonateGroupHeader:
			for _, group := range values {
				if _, ok := ctx.kubeGroups[group]; !ok {
					return trace.AccessDenied("%v, group header %q value is not allowed in roles", ImpersonationRequestDeniedMessage, group)
				}
				impersonateGroups = append(impersonateGroups, group)
			}
		default:
			return trace.AccessDenied("%v, unsupported impersonation header %q", ImpersonationRequestDeniedMessage, header)
		}
	}

	impersonateGroups = utils.Deduplicate(impersonateGroups)

	// By default, if no kubernetes_users is set (which will be a majority),
	// user will impersonate themselves, which is the backwards-compatible behavior.
	//
	// As long as at least one `kubernetes_users` is set, the forwarder will start
	// limiting the list of users allowed by the client to impersonate.
	//
	// If the users' role set does not include actual user name, it will be rejected,
	// otherwise there will be no way to exclude the user from the list).
	//
	// If the `kubernetes_users` role set includes only one user
	// (quite frequently that's the real intent), teleport will default to it,
	// otherwise it will refuse to select.
	//
	// This will enable the use case when `kubernetes_users` has just one field to
	// link the user identity with the IAM role, for example `IAM#{{external.email}}`
	//
	if impersonateUser == "" {
		switch len(ctx.kubeUsers) {
		// this is currently not possible as kube users have at least one
		// user (user name), but in case if someone breaks it, catch here
		case 0:
			return trace.AccessDenied("assumed at least one user to be present")
		// if there is deterministic choice, make it to improve user experience
		case 1:
			for user := range ctx.kubeUsers {
				impersonateUser = user
				break
			}
		default:
			return trace.AccessDenied(
				"please select a user to impersonate, refusing to select a user due to several kuberenetes_users set up for this user")
		}
	}

	if len(impersonateGroups) == 0 {
		for group := range ctx.kubeGroups {
			impersonateGroups = append(impersonateGroups, group)
		}
	}

	if !ctx.teleportCluster.isRemote {
		headers.Set(ImpersonateUserHeader, impersonateUser)

		// Make sure to overwrite the exiting headers, instead of appending to
		// them.
		headers[ImpersonateGroupHeader] = nil
		for _, group := range impersonateGroups {
			headers.Add(ImpersonateGroupHeader, group)
		}
	}
	return nil
}

// catchAll forwards all HTTP requests to the target k8s API server
func (f *Forwarder) catchAll(ctx *authContext, w http.ResponseWriter, req *http.Request) (interface{}, error) {
	sess, err := f.getOrCreateClusterSession(*ctx)
	if err != nil {
		// This error goes to kubernetes client and is not visible in the logs
		// of the teleport server if not logged here.
		f.Errorf("Failed to create cluster session: %v.", err)
		return nil, trace.Wrap(err)
	}
	if err := f.setupForwardingHeaders(sess, req); err != nil {
		// This error goes to kubernetes client and is not visible in the logs
		// of the teleport server if not logged here.
		f.Errorf("Failed to set up forwarding headers: %v.", err)
		return nil, trace.Wrap(err)
	}

	w = &responseStatusRecorder{ResponseWriter: w}
	sess.forwarder.ServeHTTP(w, req)

	if f.NewKubeService {
		// Proxy should be recording all the events, so we don't have to.
		return nil, nil
	}

	// Emit audit event.
	event := &events.KubeRequest{
		Metadata: events.Metadata{
			Type: events.KubeRequestEvent,
			Code: events.KubeRequestCode,
		},
		UserMetadata: events.UserMetadata{
			User:  ctx.User.GetName(),
			Login: ctx.User.GetName(),
		},
		ConnectionMetadata: events.ConnectionMetadata{
			RemoteAddr: req.RemoteAddr,
			LocalAddr:  sess.teleportCluster.targetAddr,
			Protocol:   events.EventProtocolKube,
		},
		ServerMetadata: events.ServerMetadata{
			ServerID:        f.ServerID,
			ServerNamespace: f.Namespace,
		},
		RequestPath:  req.URL.Path,
		Verb:         req.Method,
		ResponseCode: int32(w.(*responseStatusRecorder).getStatus()),
	}
	r := parseResourcePath(req.URL.Path)
	if r.skipEvent {
		return nil, nil
	}
	r.populateEvent(event)
	if err := f.Client.EmitAuditEvent(f.Context, event); err != nil {
		f.WithError(err).Warn("Failed to emit event.")
	}

	return nil, nil
}

func (f *Forwarder) getExecutor(ctx authContext, sess *clusterSession, req *http.Request) (remotecommand.Executor, error) {
	upgradeRoundTripper := NewSpdyRoundTripperWithDialer(roundTripperConfig{
		ctx:             req.Context(),
		authCtx:         ctx,
		dial:            sess.DialWithContext,
		tlsConfig:       sess.tlsConfig,
		followRedirects: true,
		pingPeriod:      f.PingPeriod,
	})
	rt := http.RoundTripper(upgradeRoundTripper)
	if sess.creds != nil {
		var err error
		rt, err = sess.creds.wrapTransport(rt)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return remotecommand.NewSPDYExecutorForTransports(rt, upgradeRoundTripper, req.Method, req.URL)
}

func (f *Forwarder) getDialer(ctx authContext, sess *clusterSession, req *http.Request) (httpstream.Dialer, error) {
	upgradeRoundTripper := NewSpdyRoundTripperWithDialer(roundTripperConfig{
		ctx:             req.Context(),
		authCtx:         ctx,
		dial:            sess.DialWithContext,
		tlsConfig:       sess.tlsConfig,
		followRedirects: true,
		pingPeriod:      f.PingPeriod,
	})
	rt := http.RoundTripper(upgradeRoundTripper)
	if sess.creds != nil {
		var err error
		rt, err = sess.creds.wrapTransport(rt)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	client := &http.Client{
		Transport: rt,
	}

	return spdy.NewDialer(upgradeRoundTripper, client, req.Method, req.URL), nil
}

// clusterSession contains authenticated user session to the target cluster:
// x509 short lived credentials, forwarding proxies and other data
type clusterSession struct {
	authContext
	parent    *Forwarder
	creds     *kubeCreds
	tlsConfig *tls.Config
	forwarder *forward.Forwarder
}

func (s *clusterSession) monitorConn(conn net.Conn, err error) (net.Conn, error) {
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if s.disconnectExpiredCert.IsZero() && s.clientIdleTimeout == 0 {
		return conn, nil
	}
	ctx, cancel := context.WithCancel(s.parent.ctx)
	tc := &trackingConn{
		Conn:   conn,
		clock:  s.parent.Clock,
		ctx:    ctx,
		cancel: cancel,
	}

	mon, err := srv.NewMonitor(srv.MonitorConfig{
		DisconnectExpiredCert: s.disconnectExpiredCert,
		ClientIdleTimeout:     s.clientIdleTimeout,
		Clock:                 s.parent.Clock,
		Tracker:               tc,
		Conn:                  tc,
		Context:               ctx,
		TeleportUser:          s.User.GetName(),
		ServerID:              s.parent.ServerID,
		Entry:                 s.parent.Entry,
		Emitter:               s.parent.Client,
	})
	if err != nil {
		tc.Close()
		return nil, trace.Wrap(err)
	}
	go mon.Start()
	return tc, nil
}

func (s *clusterSession) Dial(network, addr string) (net.Conn, error) {
	return s.monitorConn(s.teleportCluster.Dial(network, addr))
}

func (s *clusterSession) DialWithContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.monitorConn(s.teleportCluster.DialWithContext(ctx, network, addr))
}

type trackingConn struct {
	sync.RWMutex
	net.Conn
	clock      clockwork.Clock
	lastActive time.Time
	ctx        context.Context
	cancel     context.CancelFunc
}

// Read reads data from the connection.
// Read can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (t *trackingConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	t.UpdateClientActivity()
	return n, err
}

func (t *trackingConn) Close() error {
	t.cancel()
	return t.Conn.Close()
}

// GetClientLastActive returns time when client was last active
func (t *trackingConn) GetClientLastActive() time.Time {
	t.RLock()
	defer t.RUnlock()
	return t.lastActive
}

// UpdateClientActivity sets last recorded client activity
func (t *trackingConn) UpdateClientActivity() {
	t.Lock()
	defer t.Unlock()
	t.lastActive = t.clock.Now().UTC()
}

func (f *Forwarder) getOrCreateClusterSession(ctx authContext) (*clusterSession, error) {
	client := f.getClusterSession(ctx)
	if client != nil {
		return client, nil
	}
	return f.serializedNewClusterSession(ctx)
}

func (f *Forwarder) getClusterSession(ctx authContext) *clusterSession {
	f.Lock()
	defer f.Unlock()
	creds, ok := f.clusterSessions.Get(ctx.key())
	if !ok {
		return nil
	}
	s := creds.(*clusterSession)
	if s.teleportCluster.isRemote && s.teleportCluster.isRemoteClosed() {
		f.Debugf("Found an existing clusterSession for remote cluster %q but it has been closed. Discarding it to create a new clusterSession.", ctx.teleportCluster.name)
		f.clusterSessions.Remove(ctx.key())
		return nil
	}
	return s
}

func (f *Forwarder) serializedNewClusterSession(authContext authContext) (*clusterSession, error) {
	ctx, cancel := f.getOrCreateRequestContext(authContext.key())
	if cancel != nil {
		f.Debugf("Requesting new cluster session for %v.", authContext)
		defer cancel()
		sess, err := f.newClusterSession(authContext)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return f.setClusterSession(sess)
	}
	// cancel == nil means that another request is in progress, so simply wait until
	// it finishes or fails
	f.Debugf("Another request is in progress for %v, waiting until it gets completed.", authContext)
	select {
	case <-ctx.Done():
		sess := f.getClusterSession(authContext)
		if sess == nil {
			return nil, trace.BadParameter("failed to request certificate, try again")
		}
		return sess, nil
	case <-f.ctx.Done():
		return nil, trace.BadParameter("forwarder is closing, aborting the request")
	}
}

// TODO(awly): unit test this
func (f *Forwarder) newClusterSession(ctx authContext) (*clusterSession, error) {
	if ctx.teleportCluster.isRemote {
		return f.newClusterSessionRemoteCluster(ctx)
	}
	return f.newClusterSessionSameCluster(ctx)
}

func (f *Forwarder) newClusterSessionRemoteCluster(ctx authContext) (*clusterSession, error) {
	sess := &clusterSession{
		parent:      f,
		authContext: ctx,
	}
	var err error
	sess.tlsConfig, err = f.requestCertificate(ctx)
	if err != nil {
		f.Warningf("Failed to get certificate for %v: %v.", ctx, err)
		return nil, trace.AccessDenied("access denied: failed to authenticate with auth server")
	}
	// remote clusters use special hardcoded URL,
	// and use a special dialer
	sess.authContext.teleportCluster.targetAddr = reversetunnel.LocalKubernetes
	transport := f.newTransport(sess.Dial, sess.tlsConfig)

	sess.forwarder, err = forward.New(
		forward.FlushInterval(100*time.Millisecond),
		forward.RoundTripper(transport),
		forward.WebsocketDial(sess.Dial),
		forward.Logger(f.Entry),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return sess, nil
}

func (f *Forwarder) newClusterSessionSameCluster(ctx authContext) (*clusterSession, error) {
	kubeServices, err := f.AccessPoint.GetKubeServices(f.ctx)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}
	if len(kubeServices) == 0 && ctx.kubeCluster == ctx.teleportCluster.name {
		return f.newClusterSessionLocal(ctx)
	}
	// Validate that the requested kube cluster is registered.
	var endpoints []services.Server
outer:
	for _, s := range kubeServices {
		for _, k := range s.GetKubernetesClusters() {
			if k.Name != ctx.kubeCluster {
				continue
			}
			// TODO(awly): check RBAC
			endpoints = append(endpoints, s)
			continue outer
		}
	}
	if len(endpoints) == 0 {
		return nil, trace.NotFound("kubernetes cluster %q is not found in teleport cluster %q", ctx.kubeCluster, ctx.teleportCluster.name)
	}
	// Try to use local credentials first.
	if _, ok := f.creds[ctx.kubeCluster]; ok {
		return f.newClusterSessionLocal(ctx)
	}
	// Pick a random kubernetes_service to serve this request.
	//
	// Ideally, we should try a few of the endpoints at random until one
	// succeeds. But this is simpler for now.
	endpoint := endpoints[mathrand.Intn(len(endpoints))]
	return f.newClusterSessionDirect(ctx, endpoint)
}

func (f *Forwarder) newClusterSessionLocal(ctx authContext) (*clusterSession, error) {
	f.Debugf("Handling kubernetes session for %v using local credentials.", ctx)
	sess := &clusterSession{
		parent:      f,
		authContext: ctx,
	}
	if len(f.creds) == 0 {
		return nil, trace.NotFound("this Teleport process is not configured for direct Kubernetes access; you likely need to 'tsh login' into a leaf cluster or 'tsh kube login' into a different kubernetes cluster")
	}
	creds, ok := f.creds[ctx.kubeCluster]
	if !ok {
		return nil, trace.NotFound("kubernetes cluster %q not found", ctx.kubeCluster)
	}
	sess.creds = creds
	sess.authContext.teleportCluster.targetAddr = creds.targetAddr
	sess.tlsConfig = creds.tlsConfig

	// When running inside Kubernetes cluster or using auth/exec providers,
	// kubeconfig provides a transport wrapper that adds a bearer token to
	// requests
	//
	// When forwarding request to a remote cluster, this is not needed
	// as the proxy uses client cert auth to reach out to remote proxy.
	transport, err := creds.wrapTransport(f.newTransport(sess.Dial, sess.tlsConfig))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	fwd, err := forward.New(
		forward.FlushInterval(100*time.Millisecond),
		forward.RoundTripper(transport),
		forward.WebsocketDial(sess.Dial),
		forward.Logger(f.Entry),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sess.forwarder = fwd
	return sess, nil
}

func (f *Forwarder) newClusterSessionDirect(ctx authContext, kubeService services.Server) (*clusterSession, error) {
	f.WithFields(log.Fields{
		"kubernetes_service.name": kubeService.GetName(),
		"kubernetes_service.addr": kubeService.GetAddr(),
	}).Debugf("Kubernetes session for %v forwarded to remote kubernetes_service instance.", ctx)
	sess := &clusterSession{
		parent:      f,
		authContext: ctx,
	}
	// Set both addr and serverID, in case this is a kubernetes_service
	// connected over a tunnel.
	sess.authContext.teleportCluster.targetAddr = kubeService.GetAddr()
	sess.authContext.teleportCluster.serverID = fmt.Sprintf("%s.%s", kubeService.GetName(), ctx.teleportCluster.name)

	var err error
	sess.tlsConfig, err = f.requestCertificate(ctx)
	if err != nil {
		f.Warningf("Failed to get certificate for %v: %v.", ctx, err)
		return nil, trace.AccessDenied("access denied: failed to authenticate with auth server")
	}

	transport := f.newTransport(sess.Dial, sess.tlsConfig)

	sess.forwarder, err = forward.New(
		forward.FlushInterval(100*time.Millisecond),
		forward.RoundTripper(transport),
		forward.WebsocketDial(sess.Dial),
		forward.Logger(f.Entry),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return sess, nil
}

func (f *Forwarder) setClusterSession(sess *clusterSession) (*clusterSession, error) {
	f.Lock()
	defer f.Unlock()

	sessI, ok := f.clusterSessions.Get(sess.authContext.key())
	if ok {
		return sessI.(*clusterSession), nil
	}

	if err := f.clusterSessions.Set(sess.authContext.key(), sess, sess.authContext.sessionTTL); err != nil {
		return nil, trace.Wrap(err)
	}
	f.Debugf("Created new session for %v.", sess.authContext)
	return sess, nil
}

// DialFunc is a network dialer function that returns a network connection
type DialFunc func(string, string) (net.Conn, error)

func (f *Forwarder) newTransport(dial DialFunc, tlsConfig *tls.Config) *http.Transport {
	return &http.Transport{
		Dial:            dial,
		TLSClientConfig: tlsConfig,
		// Increase the size of the connection pool. This substantially improves the
		// performance of Teleport under load as it reduces the number of TLS
		// handshakes performed.
		MaxIdleConns:        defaults.HTTPMaxIdleConns,
		MaxIdleConnsPerHost: defaults.HTTPMaxIdleConnsPerHost,
		// IdleConnTimeout defines the maximum amount of time before idle connections
		// are closed. Leaving this unset will lead to connections open forever and
		// will cause memory leaks in a long running process.
		IdleConnTimeout: defaults.HTTPIdleTimeout,
	}
}

// getOrCreateRequestContext creates a new certificate request for a given context,
// if there is no active CSR request in progress, or returns an existing one.
// if the new context has been created, cancel function is returned as a
// second argument. Caller should call this function to signal that CSR has been
// completed or failed.
func (f *Forwarder) getOrCreateRequestContext(key string) (context.Context, context.CancelFunc) {
	f.Lock()
	defer f.Unlock()
	ctx, ok := f.activeRequests[key]
	if ok {
		return ctx, nil
	}
	ctx, cancel := context.WithCancel(context.TODO())
	f.activeRequests[key] = ctx
	return ctx, func() {
		cancel()
		f.Lock()
		defer f.Unlock()
		delete(f.activeRequests, key)
	}
}

func (f *Forwarder) requestCertificate(ctx authContext) (*tls.Config, error) {
	f.Debugf("Requesting K8s cert for %v.", ctx)
	keyPEM, _, err := f.Keygen.GenerateKeyPair("")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	privateKey, err := ssh.ParseRawPrivateKey(keyPEM)
	if err != nil {
		return nil, trace.Wrap(err, "failed to parse private key")
	}

	// Note: ctx.Identity can potentially have temporary roles granted via
	// workflow API. Always use the Subject() method to preserve the roles from
	// caller's certificate.
	identity := ctx.Identity.GetIdentity()
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
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	response, err := f.Client.ProcessKubeCSR(auth.KubeCSR{
		Username:    ctx.User.GetName(),
		ClusterName: ctx.teleportCluster.name,
		CSR:         csrPEM,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	f.Debugf("Received valid K8s cert for %v.", ctx)

	cert, err := tls.X509KeyPair(response.Cert, keyPEM)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	pool := x509.NewCertPool()
	for _, certAuthority := range response.CertAuthorities {
		ok := pool.AppendCertsFromPEM(certAuthority)
		if !ok {
			return nil, trace.BadParameter("failed to append certificates, check that kubeconfig has correctly encoded certificate authority data")
		}
	}
	tlsConfig := &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig, nil
}

func (f *Forwarder) kubeClusters() []*services.KubernetesCluster {
	res := make([]*services.KubernetesCluster, 0, len(f.creds))
	for n := range f.creds {
		res = append(res, &services.KubernetesCluster{
			Name: n,
			// TODO(awly): add labels
		})
	}
	return res
}

type responseStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseStatusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseStatusRecorder) getStatus() int {
	// http.ResponseWriter implicitly sets StatusOK, if WriteHeader hasn't been
	// explicitly called.
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}
