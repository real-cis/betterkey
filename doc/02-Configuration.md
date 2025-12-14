## Configuration

### Environment Variables

```bash
# Cluster Identity
CLUSTER_ID=production-cluster
# An FQDN or an ip address used for both memberlist cluster advertising and web service
NODE_HOST=node1.example.com
# Port for cluster internal communication
CLUSTER_PORT=6001
# Default bind address for memberlist service
BIND_ADDRESS=0.0.0.0
# Seed nodes that particicipate in initial cluster setup and master key generation
SEED_NODES=node1,node2,node3
# Peer nodes for this node
CLUSTER_PEERS=node1:6001,node2:6002,node3:6003
# Port to listen on for web service
SERVER_PORT=7001
# Memberlist cluster encryption key
CLUSTER_ENCRYPTIONKEY=<cluster-encryption-key-string>
# Local filesystem path accessible to enclave for key persistence
MASTERKEY_FOLDER=/sealed

# Valkey Storage
VALKEY_URIS=valkey:6379
VALKEY_PASSWORD=<password>
VALKEY_NAMESPACE=prod

# ACME (optional)
ACME_DNS_API_TOKEN=<dns-api-token>
ACME_OWNER=admin@example.com
SERVER_DOMAIN=betterkey.example.com
```

### Enclave Configuration 

The enclave configuration is read as a toml file. Node attestation verification compares enclave config during connection establishment. If there's a mismatch the node mutual RA-TLS will fail.

```toml
# Product Id
productId = 1
# Enable debug
debug = false
# Signer id
signerId = "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e"
# Security versions
securityVersions = [1, 2]
```

### ACME DNS Provider

Betterkey uses DNS challenge for ACME authorization and a DNS provider must be available to append and delete records in order to solve ACME challenge.

* Check `providers/dns/` for implementation example
* For custom DNS providers, adapt build to use a tag - `-tags=<dns-provider>`

### Development Mode

Set `DEV_MODE=true` to mock attestation verification (for local testing, not to be used on production):
This will

* make services mock tdx attestation verification 
* lets keystore use a dev namespace

```bash
DEV_MODE=1 docker-compose up
```
