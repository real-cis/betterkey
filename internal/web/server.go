package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/web/cert"
	"gitlab.com/real-cis/cc/betterkey/providers/dns"
	"gitlab.com/real-cis/cc/betterkey/providers/journal"
)

type KeyServer struct {
	Router                   *chi.Mux
	Port                     int
	Domain                   string
	NodeHost                 string
	server                   *http.Server
	sessions                 *SessionStore // attestation session record persistence
	keyService               KeyGenService
	challengeResponse        ChallengeResponse // challenge response for VM attestation
	sealingChallengeResponse ChallengeResponse // challenge response for sealing operations
	journal                  journal.Journal   // journal for key requests
}

func NewKeyServer(config *common.ClusterConfig, kvStore common.KeyStore,
	nodeMeta *common.NodeMeta, vault common.Vault, nodeTlsConfig *tls.Config) *KeyServer {
	router := chi.NewRouter()

	var tlsConfig *tls.Config
	if len(config.AcmeDnsToken) == 0 {
		slog.Info("acme DNS token is not configured, using node tls config for server.")
		tlsConfig = nodeTlsConfig
	} else {
		slog.Info("use acme for server")
		provider := dns.NewProvider(config.AcmeDnsToken)
		acmeConfig := &cert.AcmeConfig{
			Domain:       config.Domain,
			DnsProvider:  provider,
			AcmeOwner:    config.AcmeOwner,
			AcmeProvider: config.AcmeProvider,
			KVStore:      kvStore,
			NodeId:       config.NodeHost,
			RetryDelay:   config.AcmeRetryDelay,
			RetryCount:   config.AcmeRetryCount,
		}
		certMagic := acmeConfig.Setup()
		tlsConfig = certMagic.TLSConfig()
	}

	server := &http.Server{
		Addr:      ":" + strconv.Itoa(config.ServerPort),
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	keyStore := NewSessionKeyStore(kvStore, config.DevMode)
	sessions := NewSessionStore(keyStore)
	// VMs always fully attest themselves, devMode=false
	challengeResponse := NewAttestationProtocol(sessions, false)
	sealingChallengeResponse := NewAttestationProtocol(sessions, config.DevMode)
	keyGenService := NewKeyGenService(vault, keyStore, config.DevMode)
	journalService := journal.NewJournal(journal.Config{
		Endpoint:  config.JournalEndpoint,
		Region:    config.JournalRegion,
		AccessKey: config.JournalAccessKey,
		SecretKey: config.JournalSecretKey,
	})
	sv := &KeyServer{
		Router:                   router,
		Port:                     config.ServerPort,
		Domain:                   config.Domain,
		NodeHost:                 config.NodeHost,
		server:                   server,
		sessions:                 sessions,
		keyService:               keyGenService,
		challengeResponse:        challengeResponse,
		sealingChallengeResponse: sealingChallengeResponse,
		journal:                  journalService,
	}

	router.Use(LoggingMiddleware, DefaultHeaders)
	sv.registerRoutes()

	return sv
}

func (s *KeyServer) registerRoutes() {
	s.Router.Post("/key/init", s.handleKeyRequestInit)
	s.Router.Post("/key/finalize", s.handleKeyRequestFinalize)
	s.Router.Post("/tdx/seal/init", s.handleTdxSealInit)
	s.Router.Post("/tdx/seal/finalize", s.handleTdxSealFinalize)
	s.Router.Post("/sgx/verify", s.handleSgxQuoteVerify)
	s.Router.Get("/sgx/attestation", s.handleGenerateAttestation)
	s.Router.Get("/health", s.handleHealth)
}

func (s *KeyServer) Start() {
	go func() {
		slog.Info(fmt.Sprintf("Server listening on https://%s:%d", s.Domain, s.Port))
		if err := s.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("Server error:", "error", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop

	s.Stop()
}

func (s *KeyServer) Stop() {
	slog.Info("Shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		slog.Error("Shutdown error:", "error", err)
	}

	slog.Info("Server stopped.")
}

// asynchronously persists a journal record; non-blocking/best effort
func (s *KeyServer) logJournal(rec journal.Record) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), journalWriteTimeout)
		defer cancel()
		if err := s.journal.Write(ctx, rec); err != nil {
			slog.Warn("journal write failed", "resourceId", rec.ResourceId, "sessionId", rec.SessionId, "error", err)
		}
	}()
}
