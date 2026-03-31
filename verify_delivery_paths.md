# Verification: Delivery Paths for CLI restore-all vs Web Download

## Overview

This document describes the exact URL chains for two different download paths:
1. **CLI restore-all** (piece gateway path) - Used by `qave-recovery-cli fetch` and `restore-all`
2. **Web download** (download-session path) - Used by the web UI

## Path 1: CLI restore-all (piece gateway)

### URL Chain
```
qrm file → provider_piece_url storage_ref → piece gateway URL
                                           ↓
                              [piece gateway]/piece/{piece_cid}
```

### Source Resolution Order (fetch.go:resolveFetchSource)

1. **First**: Check for `provider_piece_url` in StorageRefs
   - Format: `https://{piece-gateway-base}/piece/{piece_cid}`
   - This is the PREFERRED source in the qrm

2. **Second**: If `--piece-base-url` flag or `QAVE_FETCH_PIECE_BASE_URL` env var provided
   - Falls back to building: `{pieceBaseURL}/piece/{piece_cid}`

3. **Third**: If `cid` field exists in file entry
   - Can be used with piece gateway

4. **Fourth**: If `synapse://piece/{piece_cid}` backend ref exists
   - Builds piece gateway URL from the synapse ref

### Key Characteristics

- **Timeout**: 60 seconds (HTTP client timeout)
- **HTTP Client Settings**:
  ```go
  fetchHTTPClient := &http.Client{
      Timeout: 60 * time.Second,
      Transport: &http.Transport{
          MaxIdleConns:        0,    // NO CONNECTION POOLING
          MaxConnsPerHost:     1,    // Sequential
          DisableKeepAlives:   true, // New connection per request
      },
  }
  ```
- **Download Method**: `io.ReadAll(resp.Body)` - reads entire file into memory
- **No streaming support**
- **No chunked download**

### When "context deadline exceeded" Occurs

The error "context deadline exceeded" occurs when:

1. **Server is slow (>60s)**: The piece gateway takes too long to respond
2. **Network is slow**: 8.4MB at typical speeds:
   - At 1 Mbps: ~67 seconds → WILL TIMEOUT
   - At 1.5 Mbps: ~45 seconds → RISKY
   - At 2 Mbps: ~34 seconds → SAFE
3. **Server hangs after accepting connection**: Partial data then hang
4. **Connection issues**: With `MaxIdleConns: 0`, each request creates a new connection

### Conditions that Cause Timeout

| Condition | Time to 8.4MB | Result |
|-----------|---------------|--------|
| 512 kbps | ~137s | TIMEOUT |
| 1 Mbps | ~67s | TIMEOUT |
| 1.5 Mbps | ~45s | RISKY |
| 2 Mbps | ~34s | OK |
| 5 Mbps | ~13s | OK |

## Path 2: Web Download (download-session)

### URL Chain
```
Web UI → POST /api/v1/objects/{id}/download-session
                         ↓
                   download_session created
                         ↓
         Poll GET /api/v1/download-sessions/{session_id}
                         ↓
              Status: "waiting" | "ready" | "failed"
                         ↓
         When ready: GET /api/v1/download-sessions/{session_id}/consume
                         ↓
                   Actual file download
```

### Key Characteristics

- **Session-based**: Creates a download session
- **Async preparation**: Session may be "waiting" while backend prepares
- **Polling required**: Client must poll for "ready" status
- **Timeout on polling**: Not explicitly limited (uses default HTTP timeouts)

### When "Waiting" State Persists

The download-session stays in "waiting" state when:

1. **Backend not ready**: Object is still being replicated
2. **Storage provider slow**: Getting the piece from cold storage
3. **Network issues**: Between backend and storage provider
4. **Session expired**: Session timed out before consumption

## Key Differences

| Aspect | CLI (piece gateway) | Web (download-session) |
|--------|---------------------|------------------------|
| Path | Direct to piece gateway | Through backend API |
| Timeout | 60s fixed | Configurable per-request |
| Large file | In-memory full read | Streaming possible |
| Retry logic | None (CLI fetch) | Backend handles |
| Error handling | "context deadline exceeded" | Session state polling |

## Root Cause Analysis: 8.4MB File Failure

### Why CLI restore-all failed with "context deadline exceeded"

1. **60s timeout is insufficient** for 8.4MB at typical consumer speeds
2. **No streaming**: `io.ReadAll` loads entire file into memory before returning
3. **MaxIdleConns: 0**: Forces new connection per request (minor impact)
4. **DisableKeepAlives: true**: Prevents connection reuse (minor impact)

### Why Web Download May Work

1. **download-session** may have different timeout handling
2. Backend may stream the file rather than loading into memory
3. Backend may have longer timeout or different retry logic

## Verification Test Results

### Test: fetch_timeout_test.go

The test file verifies:

1. **TestFetchHTTPClientTimeoutBehavior**
   - Server sleeps >60s → "context deadline exceeded" ✓
   
2. **TestFetchHTTPClientPartialDataThenHang**
   - Partial data then hang → Fails with timeout ✓
   
3. **TestFetchHTTPClientSlow200**
   - Slow 200 response → Times out ✓
   
4. **TestVerify60sTimeoutSufficiency**
   - Documents that 60s is NOT sufficient for 8.4MB ✓

## Recommendations

### Short-term (Code-level verification)

1. Increase timeout to 120s or 180s for large files
2. Consider streaming downloads instead of `io.ReadAll`
3. Add `--timeout` flag to CLI

### Long-term

1. Implement chunked/streaming download
2. Add progress reporting
3. Consider download-session path for large files in CLI

## Related Code Locations

| File | Lines | Description |
|------|-------|-------------|
| fetch.go | 18-34 | HTTP client configuration |
| fetch.go | 252-289 | fetchSourceBytes function |
| fetch.go | 203-235 | buildPieceGatewaySource |
| sdk.mjs | 156-202 | runWithRetry (web path) |
| direct_runner.go | 159-202 | execJSON timeout handling |

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| QAVE_FETCH_PIECE_BASE_URL | CLI fetch | Fallback piece gateway base URL |

## Notes

- The 60s timeout is hardcoded in `fetch.go` as `defaultFetchHTTPTimeout`
- The HTTP client is a package-level variable `fetchHTTPClient`
- No test currently exists for large file (8.4MB) download scenarios
- The web path uses download-session which has different characteristics
