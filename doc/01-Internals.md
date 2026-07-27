<!-- Copyright 2025-2026 real-cis GmbH -->
<!-- SPDX-License-Identifier: MIT -->

## Architecture

Betterkey operates as a mesh of nodes that:

1. **Form a cluster** using HashiCorp Memberlist (gossip protocol)
2. **Attest each other** via TDX/SGX quotes embedded in TLS certificates
3. **Derive a master key** through distributed consensus (seed nodes)
4. **Share the key** securely with new joining nodes
5. **Provide key derivation** through HTTPS API endpoints

![alt text](1-root-of-trust-cluster.png)

### Cluster convergence

Nodes discover each other using **Memberlist** (Gossip protocol):

- Seed nodes bootstrap the cluster by connecting to configured peer addresses
- New nodes join by contacting an existing cluster member configured as peer
- Failure detection happens automatically via heartbeat gossip
- Network partitions are detected through heartbeat verification failures

Each node maintains its state (`NO_KEY`, `SEEDING`, `VALIDATING`, `QUERY_KEY`, `READY`) and broadcasts it in cluster metadata.

### Mutual Attestation

![alt text](2-mutual-ra-tls-nodes.png) 

All node-to-node communication uses **transparent attested TLS**:

#### Certificate Generation

- Each node generates a keypair
- Hashes the public key and requests SGX quote with hash as report data
- Embeds the hardware quote in X.509 certificate extension

#### Peer Verification

- Extract quote from peer certificate
- Verify quote signature against Intel root of trust
- Validate quote binds to certificate's public key
- Check enclave properties (ProductID, SignerID, SecurityVersion, Debug flag)

This ensures that **only authorized enclaves** with matching identities can join the cluster.

### Master Key 

The **cluster master key** is the root secret for all key operations.

#### Initial cluster

When a Betterkey cluster starts for the very first time, the configured seed nodes collaborate to create a shared master key. They first elect a “master seed” by sorting their node names and picking the first one. This master seed generates a fresh 32‑byte random value that becomes the cluster master key. To add redundancy and detect inconsistencies, the non‑master seed nodes also forward the same key to each other in a gossip‑style fashion. Once every seed node has received and confirmed the same key, each one seals it to disk using SGX (binding it to that CPU and enclave identity) and moves into the `READY` state.

The key is never sent in plaintext. Seeding is a *push*, so a sender must wrap before hearing anything from the recipient; each seed node therefore publishes one attested ephemeral key — its **offer** — before any key is distributed:

```
On entering SEEDING, every seed node broadcasts
  SEED_OFFER{ eph_X, n_X, q_X }      q_X = quote(SHA512("bk-seed-offer-v1"|clusterId|eph_X|n_X))

To send the key to peer R, a holder S wraps it to R's verified offer
  transcript = SHA256(lo_pub|hi_pub|lo_nonce|hi_nonce)   // canonical order, same on both sides
  ss         = ECDH(priv_S, eph_R) = ECDH(priv_R, eph_S)
  wk         = HKDF(ss, salt=transcript, info="betterkey/seed-wrap/v1"|eph_S)
  KEYINIT{ eph_S, n_S, q_S, recipientPub: eph_R, AESGCM(wk, mk) }
```

* One quote per node per round (**N** quotes for N seed nodes), not one per pair — the offer is a reusable commitment, so the N(N−1) sends are cheap ECDH/HKDF/AEAD operations.
* Including `eph_S` in the HKDF info separates directions, so `wk(S→R) ≠ wk(R→S)` and a wrapped key cannot be reflected back at its sender.
* The cluster id is inside the offer binding, so an offer cannot be replayed into another cluster.
* `KEYINIT` carries the sender's offer inline, so it is self-contained: a recipient that missed the sender's broadcast can still verify and unwrap it.
* Offers are accepted in any pre-`READY` state, because a peer may publish its offer before this node has decided to seed; they are discarded when the round completes.
* The agreement check is unchanged — each node compares the *unwrapped* key from every other seed node and only becomes `READY` once all of them match.

#### Joining an existing cluster

When a new node wants to join a cluster that already has a master key, it does not participate in seeding. Instead, it enters the `QUERY_KEY` state and looks for any peer already in the `READY` state. The joining node then runs an **attested ephemeral key exchange** with that peer (see [Attested key exchange](#attested-key-exchange) below): the master key is wrapped to a fresh key pair that the joining enclave proved it holds, so it never travels in plaintext. After unwrapping the key, the new node immediately seals it to its local disk using its own enclave, then validates that the operation succeeded and moves itself into the `READY` state.

#### Attested key exchange

Master-key transfer does not rely on the attested TLS channel alone for confidentiality. Both sides contribute an ephemeral X25519 key generated **inside** their enclave and embed a hash of it in the report data of a fresh quote; the responder encrypts the master key to the resulting ECDH shared secret.

```
Requester                                    Responder
  eph_r, n_r
  q_r = quote(SHA512("bk-kx-req-v1"|eph_r|n_r))
       --- KEYQUERY{eph_r, n_r, q_r} --->
                                      verify q_r is bound to eph_r, n_r
                                      eph_s, n_s; ss = ECDH(eph_s, eph_r)
                                      tr = SHA256(eph_r|eph_s|n_r|n_s)
                                      q_s = quote(SHA512("bk-kx-resp-v1"|tr))
                                      wk = HKDF(ss, salt=tr, info)
       <-- KEYQUERY_RESP{eph_s, n_s, q_s, AESGCM(wk, mk)} ---
  verify q_s is bound to tr; unwrap
```

Properties:

* The wrapping key exists only inside the two enclaves that proved possession of the ephemeral keys, so an attacker who relays or intercepts the RA-TLS session obtains ciphertext only.
* Quotes are fresh per exchange, which also proves current liveness and TCB status rather than reusing the long-lived certificate quote.
* The transfer has forward secrecy: the ephemeral keys are discarded afterwards.
* The two direction labels are distinct, so a quote minted for one direction cannot be reflected back as the other; the response binding covers the full transcript, so a quote is valid for exactly one exchange.

Nodes built without an enclave configuration (non-SGX development builds) run the same exchange without quotes.

Initial seeding between seed nodes uses the same principle with a push-shaped variant — see [Initial cluster](#initial-cluster).

#### Node restart

If a node restarts and finds a sealed master key file on disk, it must verify that this key still matches the rest of the cluster. The node first unseals the master key and then performs a challenge‑response protocol with a READY peer. It sends its own node ID as a challenge. The peer encrypts this ID using the cluster master key and returns the result. The restarting node then tries to decrypt the response using its local master key; if decryption succeeds and the original node ID is recovered, it proves that the local key matches the cluster’s key. At that point, the node safely transitions back into the `READY` state.

### Heartbeat

Nodes prove **liveness and key possession** via cryptographic heartbeats:

- Every 15 seconds, each `READY` node generates a random nonce
- Node signs nonce with master key
- Heartbeat (nonce + signature) is broadcast in node metadata
- Peers verify signatures; mismatches indicate split-brain or rogue nodes

Heartbeat statistics are aggregated into 2-minute windows and exposed to application logic via `StateListener`.

### Key Storage & Encryption

**Local Storage (Master Key):**

- Stored in local filesystem as encrypted file for each node
- Encrypted using SGX - only this enclave on this CPU can decrypt

**Distributed Storage:**

- Valkey key-value store for certificate and session id store.
- All data encrypted with master key before storage

#### Key Migration 

* Keys are derived based on the node's enclave identity and the master key.
* A TDX VM using the key derivation service can continue to derive the keys as long as at least a single node is serving the key derivation requests. 
* A migration might be necessary and is feasible if in the event that no nodes are remaining and a user wishes to host their own Betterkey nodes.

### Web Service & Key Derivation

The HTTP API server starts only after the node reaches `READY` state.

#### TLS Configuration

* Uses ACME (Let's Encrypt) if `ACME_DNS_API_TOKEN` is configured
* Falls back to node's attested TLS certificate otherwise
* ACME generated keypair is persisted on valkey store sealed with the masterkey.

#### Key Derivation Endpoints

* Key derivation, at the moment, is enabled for TDX VMs, and the requesting client must pass an attestation challenge
    - Key derivation service generates a nonce and session id, and send these as an attestation challenge to the requesting client.
    - The client, upon receiving the nonce, generates a TD Report with nonce as the Report Data, and sends the signed quote back to key derivation service.
    - Key derivation service validates the nonce and quote, then derives a key seed from both MRTD and CFV measurements.

#### Key Derivation Flow

1. Client submits TDX quote, eventlog data
2. Server verifies quote/event log and extracts MRTD, CFV from Eventlog
3. Server derives a seed from `SHA256(MRTD || CFV)`, then derives key material via HKDF
4. The derived key is sent to the client in response
