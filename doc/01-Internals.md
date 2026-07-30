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
    - The client generates an ephemeral X25519 key pair inside the TD and a TD Report whose Report Data binds the nonce and that key (see below), then sends the signed quote back to key derivation service.
    - Key derivation service validates the quote, derives a key seed from both MRTD and CFV measurements, and returns the key material **encrypted to the client's ephemeral key**.

#### Attested key exchange (client key delivery)

Derived key material must not be readable by anything between the client TD and the enclave. TLS cannot provide that here: the endpoint sits behind a load balancer that **terminates TLS**, so exporter-based channel binding is impossible and the terminator sees the plaintext response. The exchange therefore ignores the transport and wraps the key to a key pair the TD proved it holds — the same construction used for cluster master-key transfer.

```
Client (in TD)                            KDS node (SGX)
  eph_c generated inside the TD
  q_c = TD quote, report_data =
        SHA512("bk-kds-req-v1" || nonce || eph_c.pub)
     --- POST /key/finalize { sessionId, quote: q_c, eventLog, ephemeralPub } --->
                            verify q_c is bound to nonce and eph_c.pub
                            eph_s ; ss = ECDH(eph_s, eph_c)
                            tr    = SHA256(eph_c.pub || eph_s.pub || nonce)
                            q_s   = SGX quote over SHA512("bk-kds-resp-v1" || tr)
                            wk    = HKDF(ss, salt=tr, info="betterkey/kds-wrap/v1")
     <--- { ephemeralPub: eph_s.pub, quote: q_s, wrappedKey: AESGCM(wk, keyResponseJSON) } ---
  verify q_s is bound to tr, then unwrap inside the TD
```

* The load balancer sees ciphertext it cannot decrypt, so TLS termination stops being a disclosure path.
* This **subsumes** channel binding: the key is encrypted to a key an attested TD proved it holds, which is stronger than proving the quote came from a given TLS session — and it is transport-independent, so future proxy changes cannot break it.
* The server quote is bound to the full transcript, so the client can authenticate the enclave end to end. That is the only server attestation available once TLS is terminated, and it works regardless of whether the node serves its own certificate or an ACME one.
* `wrappedKey` decrypts to the same `KeyResponse` JSON the legacy flow returned, so client code downstream of the unwrap is unchanged.

`/key/init` advertises the scheme so clients can detect it:

```json
{ "nonce": "...", "sessionId": "...",
  "keyExchange": "betterkey/kds-kx/v1", "keyExchangeRequired": false }
```

`KDS_ENFORCE_KEY_WRAPPING` controls enforcement and **defaults to `false`** so already-deployed clients keep working. While it is off the server still accepts a request without `ephemeralPub`, verifies the quote against the bare nonce and replies in plaintext, logging a warning per request. That legacy path offers no protection against the terminator, so **the exposure is only closed once this is set to `true`**. Turn it on after all clients are updated.

#### Attested key exchange (seal payloads)

`/tdx/seal/*` needs the same protection in the **opposite direction**: the payload to be sealed travels client → enclave, so the enclave publishes the ephemeral key and the client wraps to it.

```
Client (in TD)                            KDS node (SGX)
     --- POST /tdx/seal/init { id, mrtd, cfv }  (no payload) --->
                            eph_s generated for the session
                            q_s = SGX quote, report_data =
                                  SHA512("bk-seal-offer-v1" || nonce || eph_s.pub)
     <--- { nonce, sessionId, keyExchange, ephemeralPub: eph_s.pub, quote: q_s } ---
  verify q_s binds nonce and eph_s.pub
  eph_c generated inside the TD
  ss = ECDH(eph_c, eph_s) ; tr = SHA256(eph_c.pub || eph_s.pub || nonce)
  wk = HKDF(ss, salt=tr, info="betterkey/seal-wrap/v1")
  q_c = TD quote, report_data = SHA512("bk-seal-req-v1" || nonce || eph_c.pub)
     --- POST /tdx/seal/finalize { sessionId, quote: q_c, ephemeralPub,
                                   wrappedPayload: AESGCM(wk, payload) } --->
                            verify q_c is bound to nonce and eph_c.pub
                            unwrap the payload, then seal it as before
```

* **Omitting `payload` at init selects the wrapped flow.** A request that still carries `payload` is the legacy plaintext flow, where the terminator reads it; it logs a warning and is refused outright once `KDS_ENFORCE_KEY_WRAPPING` is on.
* The offer quote commits the enclave to `eph_s.pub`, so a client can confirm it is wrapping to a genuine enclave rather than to the terminator.
* Labels differ from the key-delivery flow (`bk-seal-*` vs `bk-kds-*`, and distinct HKDF info strings), so material from one flow cannot be replayed into the other.
* The seal **response** needs no wrapping: it is already ciphertext under a key derived from the requesting TD's own measurements.
* `eph_s`'s private half is stored in the session record rather than held in memory, because `init` and `finalize` may be served by different nodes behind the load balancer. That record lives in the Valkey store, which is sealed with the cluster master key, so it is readable only by cluster enclaves — and only for the 60-second session TTL.

#### Key Derivation Flow

1. Client submits TDX quote, eventlog data
2. Server verifies quote/event log and extracts MRTD, CFV from Eventlog
3. Server derives a seed from `SHA256(MRTD || CFV)`, then derives key material via HKDF
4. The derived key is sent to the client in response
