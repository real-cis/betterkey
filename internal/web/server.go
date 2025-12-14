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
)

type HTTPServer struct {
	Router            *chi.Mux
	Port              int
	Domain            string
	NodeHost          string
	server            *http.Server
	keyService        KeyGenService
	policyService     PolicyService
	challengeResponse ChallengeResponse
}

func NewHTTPServer(config *common.ClusterConfig, kvStore common.KeyStore,
	nodeMeta *common.NodeMeta, vault common.Vault, nodeTlsConfig *tls.Config) *HTTPServer {
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
	challengeResponse := NewAttestationProtocol(keyStore, config.DevMode)
	keyGenService := NewKeyGenService(vault, keyStore, config.DevMode)
	policyStore := NewPolicyStore(kvStore, config.DevMode)
	policyService := NewPolicyService(policyStore)
	sv := &HTTPServer{
		Router:            router,
		Port:              config.ServerPort,
		Domain:            config.Domain,
		NodeHost:          config.NodeHost,
		server:            server,
		keyService:        keyGenService,
		challengeResponse: challengeResponse,
		policyService:     policyService,
	}

	router.Use(LoggingMiddleware, DefaultHeaders)
	router.Get("/tdx/verify", sv.handleVerifyRequest)
	router.Post("/tdx/verify", sv.handleVerifyQuote)
	router.Post("/key/init", sv.handleKeyRequestInit)
	router.Post("/key/finalize", sv.handleKeyRequestFinalize)
	router.Post("/key/sign", sv.handleSigningRequest)
	router.Delete("/key/{id}", sv.handleKeyDelete)
	router.Put("/tdx/policy", sv.handlePolicyUpdate)
	router.Post("/sgx/verify", sv.handleSgxQuoteVerify)
	router.Get("/sgx/attestation", sv.handleGenerateAttestation)
	router.Get("/health", sv.handleHealth)
	return sv
}

func (s *HTTPServer) Start() {
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

func (s *HTTPServer) Stop() {
	slog.Info("Shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		slog.Error("Shutdown error:", "error", err)
	}

	slog.Info("Server stopped.")
}
