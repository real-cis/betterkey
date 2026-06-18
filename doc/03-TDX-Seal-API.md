<!-- Copyright 2025-2026 real-cis GmbH -->
<!-- SPDX-License-Identifier: MIT -->

# TDX Seal API

TDX Seal API accepts TDX measurements and boot configuration parameters to derive a symmetric encryption key, which is then used to seal (encrypt) a supplied payload using AES-256-GCM.

## Overview
The TDX seal flow is a 2-step API:

1. `POST /tdx/seal/init` verifies/stores the seal request and returns a nonce + session ID.
2. `POST /tdx/seal/finalize` verifies the TDX quote against that nonce and returns the sealed payload.

The payload is encrypted with AES-256-GCM. The response contains base64 of `nonce(12 bytes) || ciphertext`.

## Endpoints

### Seal request init

**POST** `/tdx/seal/init`

#### Request body

```json
{
  "id": "vm-id",
  "mrtd": "base64-encoded MRTD bytes",
  "cfv": "base64-encoded CFV bytes",
  "payload": "base64-encoded plaintext bytes"
}
```

#### Response

```json
{
  "nonce": "base64-encoded nonce",
  "sessionId": "session identifier for finalize"
}
```

### 2) Seal request finalize

**POST** `/tdx/seal/finalize`

#### Request body

```json
{
  "sessionId": "session ID from /tdx/seal/init",
  "quote": "base64-encoded TDX quote",
}
```

#### Response

```json
{
  "id": "vm-id",
  "sealedPayload": "base64-encoded nonce(12B)||ciphertext"
}
```

## curl example

### Init

```bash
curl -sS -X POST https://kds:port/tdx/seal/init \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "vm-123",
    "mrtd": "<base64-mrtd>",
    "cfv": "<base64-cfv>",
    "payload": "<base64-plaintext>"
  }'
```

### Finalize

```bash
curl -sS -X POST https://kds:port/tdx/seal/finalize \
  -H 'Content-Type: application/json' \
  -d '{
    "sessionId": "<session-id-from-init>",
    "quote": "<base64-tdx-quote>",
    "eventLog": "<base64-ccel-event-log>"
  }'
```

## Errors

- **400 Bad Request**: invalid JSON or invalid base64 payload/measurements.
- **401 Unauthorized**: invalid/expired `sessionId` or quote/measurement verification failure.
- **500 Internal Server Error**: internal session/sealing failure.
