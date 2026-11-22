// Package server is a trimmed down k8s.io/apiserver/pkg/server: a handler
// chain, health endpoints, post-start hooks and graceful shutdown.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/endpoints"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/endpoints/request"
)

// Config is the configuration of a GenericAPIServer.
type Config struct {
	BindAddress     string
	Port            int
	ShutdownTimeout time.Duration
	// StaticDir, when set, is served as a single page application.
	StaticDir string
	Logger    *slog.Logger
	// Listener, when set, is used instead of listening on BindAddress:Port.
	Listener net.Listener
}

type completedConfig struct {
	*Config
}

// CompletedConfig is a Config whose defaults have been filled in.
type CompletedConfig struct {
	*completedConfig
}

// Complete fills in defaults.
func (c *Config) Complete() CompletedConfig {
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = 30 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return CompletedConfig{&completedConfig{c}}
}

// PostStartHookContext is handed to post-start hooks.
type PostStartHookContext struct {
	// Context is cancelled when the server shuts down.
	context.Context
	wg *sync.WaitGroup
}

// Go runs long lived work such as a controller. Shutdown waits for every
// function started this way to return.
func (c PostStartHookContext) Go(f func()) { c.wg.Go(f) }

// PostStartHookFunc runs after the server starts listening. It must return
// promptly; long running work is started with PostStartHookContext.Go. The
// server reports ready once every hook has returned nil.
type PostStartHookFunc func(hookCtx PostStartHookContext) error

type postStartHookEntry struct {
	hook PostStartHookFunc
	done chan struct{}
}

// GenericAPIServer serves API groups plus health endpoints.
type GenericAPIServer struct {
	cfg *completedConfig

	// Mux is where API groups and extra routes are registered.
	Mux *http.ServeMux

	hooksMu   sync.Mutex
	hookOrder []string
	hooks     map[string]*postStartHookEntry
	checks    []HealthCheck
}

// HealthCheck is a named readiness check.
type HealthCheck struct {
	Name  string
	Check func(*http.Request) error
}

// New creates the server.
func (c CompletedConfig) New() (*GenericAPIServer, error) {
	return &GenericAPIServer{cfg: c.completedConfig, Mux: http.NewServeMux(), hooks: map[string]*postStartHookEntry{}}, nil
}

// InstallAPIGroup serves a group version.
func (s *GenericAPIServer) InstallAPIGroup(g *endpoints.APIGroupVersion) {
	g.InstallREST(s.Mux)
}

// AddPostStartHook registers a hook. Names must be unique.
func (s *GenericAPIServer) AddPostStartHook(name string, hook PostStartHookFunc) error {
	s.hooksMu.Lock()
	defer s.hooksMu.Unlock()
	if _, exists := s.hooks[name]; exists {
		return fmt.Errorf("post-start hook %q already registered", name)
	}
	s.hooks[name] = &postStartHookEntry{hook: hook, done: make(chan struct{})}
	s.hookOrder = append(s.hookOrder, name)
	return nil
}

// AddReadyzChecks registers readiness checks.
func (s *GenericAPIServer) AddReadyzChecks(checks ...HealthCheck) {
	s.checks = append(s.checks, checks...)
}

type preparedGenericAPIServer struct {
	*GenericAPIServer
	handler http.Handler
}

// PrepareRun installs health endpoints and builds the handler chain.
func (s *GenericAPIServer) PrepareRun() preparedGenericAPIServer {
	s.Mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	s.Mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	s.Mux.HandleFunc("GET /readyz", s.serveReadyz)
	if s.cfg.StaticDir != "" {
		s.Mux.Handle("/", spaHandler(s.cfg.StaticDir))
	}

	// The chain is built inside out, like DefaultBuildHandlerChain.
	var h http.Handler = s.Mux
	h = WithLogging(h, s.cfg.Logger)
	h = WithRequestInfo(h, &request.RequestInfoFactory{APIPrefix: "apis"})
	h = WithPanicRecovery(h, s.cfg.Logger)
	return preparedGenericAPIServer{GenericAPIServer: s, handler: h}
}

func (s *GenericAPIServer) serveReadyz(w http.ResponseWriter, r *http.Request) {
	var failed []string
	s.hooksMu.Lock()
	for _, name := range s.hookOrder {
		select {
		case <-s.hooks[name].done:
		default:
			failed = append(failed, "poststarthook/"+name)
		}
	}
	s.hooksMu.Unlock()
	for _, c := range s.checks {
		if err := c.Check(r); err != nil {
			failed = append(failed, c.Name+": "+err.Error())
		}
	}
	if len(failed) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		for _, f := range failed {
			_, _ = fmt.Fprintf(w, "[-]%s\n", f)
		}
		return
	}
	_, _ = w.Write([]byte("ok"))
}

// Run serves until ctx is cancelled, then shuts down gracefully and waits
// for post-start hooks (controllers) to return.
func (s preparedGenericAPIServer) Run(ctx context.Context) error {
	log := s.cfg.Logger
	ln := s.cfg.Listener
	if ln == nil {
		addr := net.JoinHostPort(s.cfg.BindAddress, strconv.Itoa(s.cfg.Port))
		var err error
		if ln, err = net.Listen("tcp", addr); err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
	}
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: watch streams are long lived.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("[server] Serving", "addr", "http://"+ln.Addr().String())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	var hooksWG sync.WaitGroup
	hookCtx := PostStartHookContext{Context: ctx, wg: &hooksWG}
	s.hooksMu.Lock()
	for _, name := range s.hookOrder {
		entry := s.hooks[name]
		if err := entry.hook(hookCtx); err != nil {
			log.Error("[server] Post-start hook failed", "hook", name, "err", err)
			continue // stays unready
		}
		close(entry.done)
	}
	s.hooksMu.Unlock()

	select {
	case err := <-serveErr:
		if err != nil {
			return err
		}
	case <-ctx.Done():
	}

	log.Info("[server] Shutting down", "timeout", s.cfg.ShutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()
	err := srv.Shutdown(shutdownCtx)
	hooksWG.Wait()
	return err
}
