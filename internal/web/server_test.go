// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package web

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

// Mock implementations
type MockKeyStore struct {
	mock.Mock
}

func (m *MockKeyStore) Read(id string) ([]byte, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockKeyStore) Write(id string, key []byte) error {
	args := m.Called(id, key)
	return args.Error(0)
}

func (m *MockKeyStore) WriteWithTTL(id string, key []byte, ttl int) error {
	args := m.Called(id, key, ttl)
	return args.Error(0)
}

func (m *MockKeyStore) WriteNX(id string, key []byte, ttl int) (bool, error) {
	args := m.Called(id, key, ttl)
	return args.Bool(0), args.Error(1)
}

func (m *MockKeyStore) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockKeyStore) Exists(id string) (int64, error) {
	args := m.Called(id)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockKeyStore) HasNil(err error) bool {
	args := m.Called(err)
	return args.Bool(0)
}

func (m *MockKeyStore) List(prefix string, recursive bool) ([]string, error) {
	args := m.Called(prefix, recursive)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockKeyStore) Stat(id string) (*common.StorageStat, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*common.StorageStat), args.Error(1)
}

type MockVault struct {
	mock.Mock
}

func (m *MockVault) Seal(data []byte) ([]byte, error) {
	args := m.Called(data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockVault) Unseal(data []byte) ([]byte, error) {
	args := m.Called(data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockVault) HKDF(data []byte, info string, length int) ([]byte, error) {
	args := m.Called(data, info, length)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func createTestConfig() *common.ClusterConfig {
	return &common.ClusterConfig{
		Id:              "test-cluster",
		Port:            7946,
		ServerPort:      8443,
		Domain:          "test.example.com",
		NodeHost:        "node1",
		DevMode:         true,
		AcmeDnsToken:    "", // Empty to use node TLS
		AcmeOwner:       "test@example.com",
		AcmeProvider:    "https://acme-staging-v02.api.letsencrypt.org/directory",
		AcmeRetryDelay:  1,
		AcmeRetryCount:  3,
		ValkeyNamespace: "test",
	}
}

func createTestNodeMeta() *common.NodeMeta {
	return &common.NodeMeta{
		Id:        "node1",
		ClusterId: "test-cluster",
		State:     5, // READY
		HeartBeat: &common.HeartBeat{
			Nonce: "test-nonce",
			Value: "test-value",
		},
	}
}

func createTestTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

func TestNewHTTPServer(t *testing.T) {
	tests := []struct {
		name           string
		acmeDnsToken   string
		expectedLog    string
		setupMocks     func(*MockKeyStore, *MockVault)
		validateServer func(*testing.T, *KeyServer)
	}{
		{
			name:         "Create server with node TLS config",
			acmeDnsToken: "",
			expectedLog:  "using node tls config",
			setupMocks: func(ks *MockKeyStore, v *MockVault) {
				// No specific mocks needed for initialization
			},
			validateServer: func(t *testing.T, server *KeyServer) {
				assert.NotNil(t, server.Router)
				assert.Equal(t, 8443, server.Port)
				assert.Equal(t, "test.example.com", server.Domain)
				assert.Equal(t, "node1", server.NodeHost)
				assert.NotNil(t, server.server)
				assert.NotNil(t, server.keyService)
				assert.NotNil(t, server.challengeResponse)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.AcmeDnsToken = tt.acmeDnsToken

			mockKVStore := new(MockKeyStore)
			mockVault := new(MockVault)
			nodeMeta := createTestNodeMeta()
			tlsConfig := createTestTLSConfig()

			tt.setupMocks(mockKVStore, mockVault)

			server := NewKeyServer(config, nil, mockKVStore, nodeMeta, mockVault, tlsConfig)

			tt.validateServer(t, server)

			mockKVStore.AssertExpectations(t)
			mockVault.AssertExpectations(t)
		})
	}
}

func TestHTTPServerRoutes(t *testing.T) {
	config := createTestConfig()
	mockKVStore := new(MockKeyStore)
	mockVault := new(MockVault)
	nodeMeta := createTestNodeMeta()
	tlsConfig := createTestTLSConfig()

	server := NewKeyServer(config, nil, mockKVStore, nodeMeta, mockVault, tlsConfig)

	// Check that routes exist in the router
	chiRoutes := server.Router.Routes()
	assert.NotEmpty(t, chiRoutes, "Router should have routes")

	// Verify some key routes are registered
	found := 0
	for _, route := range chiRoutes {
		if route.Pattern == "/health" ||
			route.Pattern == "/tdx/verify" ||
			route.Pattern == "/key/init" {
			found++
		}
	}
	assert.Greater(t, found, 0, "Key routes should be registered")
}

func TestHTTPServerHealthEndpoint(t *testing.T) {
	config := createTestConfig()
	mockKVStore := new(MockKeyStore)
	mockVault := new(MockVault)
	nodeMeta := createTestNodeMeta()
	tlsConfig := createTestTLSConfig()

	server := NewKeyServer(config, nil, mockKVStore, nodeMeta, mockVault, tlsConfig)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	body, err := io.ReadAll(w.Body)
	assert.NoError(t, err)
	assert.NotEmpty(t, body)
}

func TestHTTPServerMiddleware(t *testing.T) {
	config := createTestConfig()
	mockKVStore := new(MockKeyStore)
	mockVault := new(MockVault)
	nodeMeta := createTestNodeMeta()
	tlsConfig := createTestTLSConfig()

	server := NewKeyServer(config, nil, mockKVStore, nodeMeta, mockVault, tlsConfig)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	// Check that default headers middleware is applied
	contentType := w.Header().Get("Content-Type")
	assert.NotEmpty(t, contentType, "Content-Type header should be set by middleware")
}

func TestHTTPServerTLSConfiguration(t *testing.T) {
	tests := []struct {
		name         string
		acmeDnsToken string
		checkTLS     func(*testing.T, *tls.Config)
	}{
		{
			name:         "Node TLS config used when no ACME token",
			acmeDnsToken: "",
			checkTLS: func(t *testing.T, tlsConfig *tls.Config) {
				assert.NotNil(t, tlsConfig)
				assert.True(t, tlsConfig.InsecureSkipVerify)
				assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.AcmeDnsToken = tt.acmeDnsToken

			mockKVStore := new(MockKeyStore)
			mockVault := new(MockVault)
			nodeMeta := createTestNodeMeta()
			tlsConfig := createTestTLSConfig()

			server := NewKeyServer(config, nil, mockKVStore, nodeMeta, mockVault, tlsConfig)

			tt.checkTLS(t, server.server.TLSConfig)
		})
	}
}

func TestHTTPServerConfiguration(t *testing.T) {
	config := createTestConfig()
	config.ServerPort = 9443
	config.Domain = "custom.domain.com"
	config.NodeHost = "custom-node"

	mockKVStore := new(MockKeyStore)
	mockVault := new(MockVault)
	nodeMeta := createTestNodeMeta()
	tlsConfig := createTestTLSConfig()

	server := NewKeyServer(config, nil, mockKVStore, nodeMeta, mockVault, tlsConfig)

	assert.Equal(t, 9443, server.Port)
	assert.Equal(t, "custom.domain.com", server.Domain)
	assert.Equal(t, "custom-node", server.NodeHost)
	assert.Equal(t, ":9443", server.server.Addr)
}

func TestHTTPServerServicesInitialization(t *testing.T) {
	config := createTestConfig()
	mockKVStore := new(MockKeyStore)
	mockVault := new(MockVault)
	nodeMeta := createTestNodeMeta()
	tlsConfig := createTestTLSConfig()

	server := NewKeyServer(config, nil, mockKVStore, nodeMeta, mockVault, tlsConfig)

	// Verify all services are properly initialized
	assert.NotNil(t, server.keyService, "KeyGenService should be initialized")
	assert.NotNil(t, server.challengeResponse, "ChallengeResponse should be initialized")

	// Verify server configuration
	assert.NotNil(t, server.server, "HTTP server should be initialized")
	assert.NotNil(t, server.server.Handler, "HTTP server handler should be set")
	assert.NotNil(t, server.server.TLSConfig, "HTTP server TLS config should be set")
}

func TestHTTPServerDevModeConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		devMode bool
	}{
		{
			name:    "Development mode enabled",
			devMode: true,
		},
		{
			name:    "Production mode",
			devMode: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.DevMode = tt.devMode

			mockKVStore := new(MockKeyStore)
			mockVault := new(MockVault)
			nodeMeta := createTestNodeMeta()
			tlsConfig := createTestTLSConfig()

			server := NewKeyServer(config, nil, mockKVStore, nodeMeta, mockVault, tlsConfig)

			assert.NotNil(t, server)
			// Services should be initialized regardless of dev mode
			assert.NotNil(t, server.keyService)
			assert.NotNil(t, server.challengeResponse)
		})
	}
}
