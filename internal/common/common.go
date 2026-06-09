package common

import (
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/caarlos0/env/v11"
)

var ErrNoEncryptionService = errors.New("no encryption service (missing masterkey)")
var ErrHeartBeatNonceMismatched = errors.New("nonce mismatched")

// ClusterConfig holds the configuration for the node/cluster
type ClusterConfig struct {
	Id              string   `env:"CLUSTER_ID"`
	EncryptionKey   string   `env:"CLUSTER_ENCRYPTIONKEY"`
	Port            uint32   `env:"CLUSTER_PORT"`
	PeerAddresses   []string `env:"CLUSTER_PEERS"`
	SeedNodes       []string `env:"SEED_NODES"`
	BindAddress     string   `env:"BIND_ADDRESS" envDefault:"0.0.0.0"`
	NodeHost        string   `env:"NODE_HOST"`
	MasterKeyFolder string   `env:"MASTERKEY_FOLDER" envDefault:"/sealed"`
	ValkeyUris      []string `env:"VALKEY_URIS"`
	ValkeyUser      string   `env:"VALKEY_USER"`
	ValkeyPassword  string   `env:"VALKEY_PASSWORD"`
	ValkeyNamespace string   `env:"VALKEY_NAMESPACE"`
	ValkeyTLS       bool     `env:"VALKEY_TLS" envDefault:"false"`
	Domain          string   `env:"SERVER_DOMAIN"`
	ServerPort      int      `env:"SERVER_PORT"`
	AcmeDnsToken    string   `env:"ACME_DNS_API_TOKEN"`
	AcmeOwner       string   `env:"ACME_OWNER"`
	AcmeRetryDelay  int      `env:"ACME_RETRY_DELAY" envDefault:"5"`
	AcmeRetryCount  int      `env:"ACME_RETRY_COUNT" envDefault:"10"`
	AcmeProvider    string   `env:"ACME_PROVIDER" envDefault:"https://acme-v02.api.letsencrypt.org/directory"`
	DevMode         bool     `env:"DEV_MODE" envDefault:"true"`
}

// Configuration for the SGX enclave
type EnclaveConfig struct {
	ProductId        uint16 `toml:"productId"`
	Debug            bool   `toml:"debug"`
	SignerId         string `toml:"signerId"`
	SecurityVersions []uint `toml:"securityVersions"`
}

type NodeInfo struct {
	Id        string `json:"id"`
	ClusterId string `json:"clusterId"`
}

type MasterSecret struct {
	Secret    string `json:"secret"`
	CreatorId string `json:"creatorId"`
	Created   uint64 `json:"created"`
}

type NodeMeta struct {
	Id        string     `json:"id"`
	ClusterId string     `json:"clusterId"`
	State     int        `json:"state"`
	HeartBeat *HeartBeat `json:"heartbeat"`
}

type Member struct {
	NodeInfo     *NodeInfo     `json:"nodeInfo"`
	MasterSecret *MasterSecret `json:"masterSecret"`
}

type HeartBeat struct {
	Nonce string `json:"nonce"`
	Value string `json:"value"`
}

type HeartBeatWindow struct {
	//lowest timestamp in unix time (seconds)
	From int64
	//window of events (seconds)
	Window int64
	//map nodeId to each entry in window
	Stats *map[string]*HeartBeatStat
}

type HeartBeatStat struct {
	Total, Errors int
}

type StorageStat struct {
	Size    int64
	ModTime time.Time
}

type NodeTLSConfig interface {
	ServerTlsConfig() *tls.Config
	ClientTlsConfig() *tls.Config
}

// abstraction of Node without internal memberlist,valkey
type ClusterNode interface {
	NodeStatus() *NodeMeta
	ActiveMemberNodes() []*NodeMeta
	Start()
	Shutdown()
	KVDatabase() KeyStore
}

type SGXReport struct {
	Data             string   `json:"data"`               // The report data that has been included in the report (hex).
	SecurityVersion  uint     `json:"securityVersion"`    // Security version of the enclave. For SGX enclaves, this is the ISVSVN value.
	Debug            bool     `json:"debug"`              // If true, the report is for a debug enclave.
	UniqueID         string   `json:"mrEnclave"`          // The unique ID for the enclave. For SGX enclaves, this is the MRENCLAVE value (hex).
	SignerID         string   `json:"mrSigner"`           // The signer ID for the enclave. For SGX enclaves, this is the MRSIGNER value (hex).
	ProductID        uint16   `json:"isvProdId"`          // The Product ID for the enclave. For SGX enclaves, this is the ISVPRODID value.
	TCBStatus        string   `json:"tcbStatus"`          // The status of the enclave's TCB level.
	TCBAdvisories    []string `json:"tcbAdvisories"`      // IDs of Intel security advisories that provide insight into the reasons when the TCB status is not UpToDate.
	TCBAdvisoriesErr string   `json:"tcbAdvisoriesError"` // Error that occurred while getting the advisory array (if any).
}

const (
	STORE_PREFIX_RSA_KEY           string = "rsa:"
	STORE_PREFIX_ECDSA_KEY         string = "ecdsa:"
	STORE_PREFIX_SESSION           string = "session:"
	STORE_PREFIX_DEV               string = "dev:"
	KEY_REQ_SESSION_EXPIRY_SECONDS int    = 1 * 60
	KEY_GEN_CONTEXT_EC             string = "context-ec-keypair"
	KEY_GEN_CONTEXT_SYMMETRIC      string = "context-symmetric-secret"
)

func ReadClusterConfig() (*ClusterConfig, error) {
	var config ClusterConfig
	err := env.Parse(&config)
	return &config, err
}

func ReadEnclaveConfig(path string) (*EnclaveConfig, error) {
	var config EnclaveConfig
	_, err := toml.DecodeFile(path, &config)
	return &config, err
}

func ParseConfig() (*EnclaveConfig, *ClusterConfig) {
	var path string
	flag.StringVar(&path, "config", "", "provide config file")
	flag.Parse()

	enclaveCfg, err := ReadEnclaveConfig(path)
	if err != nil {
		slog.Error("cannot load server-config", "error", err)
		panic(err)
	}

	clusterCfg, err := ReadClusterConfig()
	if err != nil {
		slog.Error("Failed to parse configuration", "error", err)
		panic(err)
	}

	return enclaveCfg, clusterCfg
}
