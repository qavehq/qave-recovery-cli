package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultFetchOutputDir   = "qave-fetched"
	pieceGatewayBaseURLEnv  = "QAVE_FETCH_PIECE_BASE_URL"
	recoveryPieceHostTypo   = "calibration-pdp.infrafolio.com"
	recoveryPieceHostFixed  = "caliberation-pdp.infrafolio.com"

	// Fetch timeout defaults — tuned for disaster-recovery "last resort" retrieval
	// where completing the download matters more than speed.
	defaultFetchOverallTimeout    = 6 * time.Hour       // hard cap; 0 = no limit
	defaultFetchInactivityTimeout = 10 * time.Minute    // stall detection
	defaultFetchConnectTimeout    = 60 * time.Second    // time to receive response headers

	fetchOverallTimeoutEnv    = "QAVE_FETCH_OVERALL_TIMEOUT_SECONDS"
	fetchInactivityTimeoutEnv = "QAVE_FETCH_INACTIVITY_TIMEOUT_SECONDS"
)

// fetchTimeoutConfig holds the resolved timeout settings for a fetch operation.
type fetchTimeoutConfig struct {
	Overall    time.Duration // hard cap on total download time; 0 = unlimited
	Inactivity time.Duration // max time between any two Read() calls returning data
}

func loadFetchTimeoutConfig() fetchTimeoutConfig {
	return fetchTimeoutConfig{
		Overall:    parseDurationEnvSeconds(fetchOverallTimeoutEnv, defaultFetchOverallTimeout),
		Inactivity: parseDurationEnvSeconds(fetchInactivityTimeoutEnv, defaultFetchInactivityTimeout),
	}
}

func parseDurationEnvSeconds(envKey string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw == "" {
		return fallback
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds < 0 {
		return fallback
	}
	if seconds == 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

var fetchHTTPClient = &http.Client{
	// No overall Client.Timeout — the hard cap is enforced via context, and
	// body reads are guarded by the inactivity timeout wrapper.  Only the
	// response-header phase uses a fixed deadline (via Transport).
	Transport: &http.Transport{
		MaxIdleConns:          0,
		MaxConnsPerHost:       1,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		ReadBufferSize:        256 * 1024,
		WriteBufferSize:       256 * 1024,
		ResponseHeaderTimeout: defaultFetchConnectTimeout,
	},
}

type fetchSelection struct {
	file  recoveryMapFileIndex
	index int
}

type fetchSource struct {
	kind        string
	description string
	location    string
}

type fetchedArtifact struct {
	filePath     string
	metadataPath string
	bytesWritten int64
}

type fetchMetadata struct {
	MapID       string                  `json:"map_id"`
	FileID      string                  `json:"file_id,omitempty"`
	VaultOwner  string                  `json:"vault_owner"`
	FileName    string                  `json:"file_name"`
	CID         string                  `json:"cid,omitempty"`
	StorageRefs []recoveryMapStorageRef `json:"storage_refs,omitempty"`
	Signer      string                  `json:"signer"`
	FetchSource string                  `json:"fetch_source"`
	FetchedAt   string                  `json:"fetched_at"`
	OutputKind  string                  `json:"output_kind"`
	ByteLength  int64                   `json:"byte_length"`
}

func parseFetchArgs(args []string) (string, string, string, string, string, error) {
	if len(args) < 5 {
		return "", "", "", "", "", newCLIError("USAGE", "fetch requires: qave-recovery-cli fetch <map.qrm> --signer <metamask|manual> --file <name|cid|index>")
	}

	pathArg := args[0]
	signer := ""
	fileSelector := ""
	outputDir := defaultFetchOutputDir
	pieceBaseURL := strings.TrimSpace(os.Getenv(pieceGatewayBaseURLEnv))

	for index := 1; index < len(args); index += 2 {
		if index+1 >= len(args) {
			return "", "", "", "", "", newCLIError("USAGE", "fetch flags must be key/value pairs")
		}
		key := strings.TrimSpace(args[index])
		value := strings.TrimSpace(args[index+1])
		switch key {
		case "--signer":
			signer = strings.ToLower(value)
		case "--file":
			fileSelector = value
		case "--output-dir":
			if value != "" {
				outputDir = value
			}
		case "--piece-base-url":
			pieceBaseURL = value
		default:
			return "", "", "", "", "", newCLIError("USAGE", "unsupported fetch flag "+key)
		}
	}

	if signer != "metamask" && signer != "manual" {
		return "", "", "", "", "", newCLIError("UNSUPPORTED_SIGNER", "supported signers are metamask and manual")
	}
	if strings.TrimSpace(fileSelector) == "" {
		return "", "", "", "", "", newCLIError("USAGE", "fetch requires --file <name|cid|index>")
	}
	return pathArg, signer, fileSelector, outputDir, pieceBaseURL, nil
}

func selectRecoveryFile(payload recoveryMapPayload, selector string) (fetchSelection, error) {
	trimmed := strings.TrimSpace(selector)
	if trimmed == "" {
		return fetchSelection{}, newCLIError("FILE_NOT_FOUND_IN_MAP", "file selector is empty")
	}

	if numeric, err := strconv.Atoi(trimmed); err == nil {
		index := numeric - 1
		if index < 0 || index >= len(payload.FileIndex) {
			return fetchSelection{}, newCLIError("FILE_NOT_FOUND_IN_MAP", "file index is outside the qrm file list")
		}
		return fetchSelection{file: payload.FileIndex[index], index: index}, nil
	}

	for index, file := range payload.FileIndex {
		if strings.EqualFold(strings.TrimSpace(file.Name), trimmed) {
			return fetchSelection{file: file, index: index}, nil
		}
	}

	for index, file := range payload.FileIndex {
		if strings.EqualFold(strings.TrimSpace(file.CID), trimmed) {
			return fetchSelection{file: file, index: index}, nil
		}
	}

	return fetchSelection{}, newCLIError("FILE_NOT_FOUND_IN_MAP", "file selector does not match any file in the recovery map")
}

func resolveFetchSource(file recoveryMapFileIndex, pieceBaseURL string, fetchSources []recoveryPackageFetchSource) (fetchSource, error) {
	fileID := strings.TrimSpace(file.FileID)

	// Priority 1: payload.FetchSources SourceRef as direct URL (Recovery Package v1 contract)
	if fileID != "" && len(fetchSources) > 0 {
		for _, fs := range fetchSources {
			if strings.TrimSpace(fs.FileID) != fileID {
				continue
			}
			if source, ok := resolveDirectFetchSourceRef(fs); ok {
				return source, nil
			}
		}
	}

	// Priority 2: file.StorageRefs / file.CID direct URLs (legacy compat)
	if direct, ok := firstDirectFetchLocation(file); ok {
		return direct, nil
	}

	// Priority 3: payload.FetchSources PieceRef/CID via piece gateway
	if fileID != "" && len(fetchSources) > 0 {
		for _, fs := range fetchSources {
			if strings.TrimSpace(fs.FileID) != fileID {
				continue
			}
			if source, ok := resolveGatewayFetchSourceRef(fs, pieceBaseURL); ok {
				return source, nil
			}
		}
	}

	// Priority 4: file.CID via piece gateway fallback
	if trimmedBase := normalizeRecoveryPieceGatewayURLCLI(pieceBaseURL); trimmedBase != "" {
		if source, ok, err := buildPieceGatewaySource(file, trimmedBase); err != nil {
			return fetchSource{}, err
		} else if ok {
			return source, nil
		}
	}

	if len(file.StorageRefs) == 0 && strings.TrimSpace(file.CID) == "" && len(fetchSources) == 0 {
		return fetchSource{}, newCLIError("FWSS_REF_NOT_FOUND", "file does not contain any fetchable storage reference")
	}

	return fetchSource{}, newCLIError("UNSUPPORTED_FETCH_SOURCE", "qrm does not contain a supported direct fetch source for this file")
}

// resolveDirectFetchSourceRef tries to resolve a FetchSource's SourceRef as a direct
// fetchable URL (http/https/file). Returns false if SourceRef is not a valid URL.
func resolveDirectFetchSourceRef(fs recoveryPackageFetchSource) (fetchSource, bool) {
	sourceRef := normalizeRecoveryPieceGatewayURLCLI(strings.TrimSpace(fs.SourceRef))
	if sourceRef == "" {
		return fetchSource{}, false
	}
	parsed, err := url.Parse(sourceRef)
	if err != nil {
		return fetchSource{}, false
	}
	sourceType := strings.TrimSpace(fs.SourceType)
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "file":
		return fetchSource{
			kind:        sourceType,
			description: sourceType + ":" + sourceRef,
			location:    sourceRef,
		}, true
	}
	return fetchSource{}, false
}

// resolveGatewayFetchSourceRef tries to resolve a FetchSource's PieceRef or CID
// through a piece gateway. Returns false if no gateway source can be built.
func resolveGatewayFetchSourceRef(fs recoveryPackageFetchSource, pieceBaseURL string) (fetchSource, bool) {
	// Try PieceRef with piece gateway
	if fs.PieceRef != nil {
		if source, ok := buildPieceGatewayFromCID(strings.TrimSpace(*fs.PieceRef), pieceBaseURL); ok {
			return source, true
		}
	}

	// Try CID as direct URL first, then with piece gateway
	if fs.CID != nil {
		cid := strings.TrimSpace(*fs.CID)
		if cid != "" {
			if parsed, err := url.Parse(cid); err == nil {
				switch strings.ToLower(parsed.Scheme) {
				case "http", "https", "file":
					return fetchSource{
						kind:        "cid",
						description: "cid:" + cid,
						location:    cid,
					}, true
				}
			}
			if source, ok := buildPieceGatewayFromCID(cid, pieceBaseURL); ok {
				return source, true
			}
		}
	}

	return fetchSource{}, false
}

// buildPieceGatewayFromCID builds a piece gateway fetchSource from a CID and base URL.
func buildPieceGatewayFromCID(cid string, pieceBaseURL string) (fetchSource, bool) {
	trimmedBase := normalizeRecoveryPieceGatewayURLCLI(pieceBaseURL)
	if trimmedBase == "" || cid == "" {
		return fetchSource{}, false
	}
	base, err := url.Parse(strings.TrimRight(trimmedBase, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return fetchSource{}, false
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/piece/" + url.PathEscape(cid)
	base.RawPath = ""
	return fetchSource{
		kind:        "piece_gateway",
		description: "piece_gateway:" + cid,
		location:    base.String(),
	}, true
}

func firstDirectFetchLocation(file recoveryMapFileIndex) (fetchSource, bool) {
	for _, ref := range file.StorageRefs {
		location := normalizeRecoveryPieceGatewayURLCLI(ref.Value)
		kind := strings.TrimSpace(ref.Kind)
		if location == "" {
			continue
		}
		if kind == "provider_piece_url" {
			if parsed, err := url.Parse(location); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
				return fetchSource{
					kind:        kind,
					description: "provider_piece_url:" + location,
					location:    location,
				}, true
			}
		}
		if parsed, err := url.Parse(location); err == nil {
			switch strings.ToLower(parsed.Scheme) {
			case "http", "https", "file":
				return fetchSource{
					kind:        kind,
					description: kind + ":" + location,
					location:    location,
				}, true
			}
		}
	}

	cid := strings.TrimSpace(file.CID)
	if cid == "" {
		return fetchSource{}, false
	}
	if parsed, err := url.Parse(cid); err == nil {
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https", "file":
			return fetchSource{
				kind:        "cid",
				description: "cid:" + cid,
				location:    cid,
			}, true
		}
	}
	return fetchSource{}, false
}

func buildPieceGatewaySource(file recoveryMapFileIndex, pieceBaseURL string) (fetchSource, bool, error) {
	pieceCID := strings.TrimSpace(file.CID)
	if pieceCID == "" {
		for _, ref := range file.StorageRefs {
			if strings.TrimSpace(ref.Kind) != "provider_operation_ref" {
				continue
			}
			parsedCID, ok, err := extractSynapsePieceCID(ref.Value)
			if err != nil {
				return fetchSource{}, false, err
			}
			if ok {
				pieceCID = parsedCID
				break
			}
		}
	}
	if pieceCID == "" {
		return fetchSource{}, false, nil
	}

	base, err := url.Parse(strings.TrimRight(pieceBaseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return fetchSource{}, false, newCLIError("UNSUPPORTED_FETCH_SOURCE", "piece gateway base url is invalid")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/piece/" + url.PathEscape(pieceCID)
	base.RawPath = ""
	return fetchSource{
		kind:        "piece_gateway",
		description: "piece_gateway:" + pieceCID,
		location:    base.String(),
	}, true, nil
}

func normalizeRecoveryPieceGatewayURLCLI(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return trimmed
	}

	if !strings.EqualFold(strings.TrimSpace(parsed.Hostname()), recoveryPieceHostTypo) {
		return trimmed
	}

	port := parsed.Port()
	if port != "" {
		parsed.Host = recoveryPieceHostFixed + ":" + port
	} else {
		parsed.Host = recoveryPieceHostFixed
	}
	return parsed.String()
}

func extractSynapsePieceCID(value string) (string, bool, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return "", false, nil
	}
	if parsed.Scheme != "synapse" || parsed.Host != "piece" {
		return "", false, nil
	}
	pieceCID := strings.TrimSpace(strings.TrimPrefix(parsed.Path, "/"))
	if pieceCID == "" {
		return "", false, newCLIError("FWSS_REF_NOT_FOUND", "synapse backend ref is missing piece cid")
	}
	return pieceCID, true, nil
}

func fetchSourceBytes(ctx context.Context, source fetchSource) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := copyFetchSource(ctx, source, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func copyFetchSource(ctx context.Context, source fetchSource, dst io.Writer) (int64, error) {
	parsed, err := url.Parse(source.location)
	if err != nil {
		return 0, newCLIError("UNSUPPORTED_FETCH_SOURCE", "fetch source URL is invalid")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "file":
		if parsed.Host != "" && parsed.Host != "localhost" {
			return 0, newCLIError("UNSUPPORTED_FETCH_SOURCE", "file fetch source must not use a remote host")
		}
		f, err := os.Open(parsed.Path)
		if err != nil {
			return 0, newCLIError("FWSS_FETCH_FAILED", "failed to read encrypted blob from local file source")
		}
		defer f.Close()
		written, err := io.Copy(dst, f)
		if err != nil {
			return 0, newCLIError("FWSS_FETCH_FAILED", fmt.Sprintf("failed to copy encrypted blob from local file source: %s", err.Error()))
		}
		return written, nil
	case "http", "https":
		tc := loadFetchTimeoutConfig()
		fetchCtx := ctx
		var cancel context.CancelFunc
		if tc.Overall > 0 {
			fetchCtx, cancel = context.WithTimeout(ctx, tc.Overall)
		} else {
			fetchCtx, cancel = context.WithCancel(ctx)
		}
		defer cancel()

		req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, source.location, nil)
		if err != nil {
			return 0, newCLIError("FWSS_FETCH_FAILED", "failed to build fetch request")
		}
		resp, err := fetchHTTPClient.Do(req)
		if err != nil {
			if fetchCtx.Err() != nil {
				return 0, newCLIError("FWSS_FETCH_FAILED", "fetch source overall timeout exceeded")
			}
			return 0, newCLIError("FWSS_FETCH_FAILED", "failed to reach fetch source")
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return 0, newCLIError("FWSS_FETCH_FAILED", fmt.Sprintf("fetch source returned HTTP %d", resp.StatusCode))
		}
		body := io.Reader(resp.Body)
		if tc.Inactivity > 0 {
			body = &inactivityReader{r: resp.Body, timeout: tc.Inactivity, timer: time.NewTimer(tc.Inactivity)}
		}
		written, err := io.Copy(dst, body)
		if err != nil {
			if fetchCtx.Err() != nil {
				return written, newCLIError("FWSS_FETCH_FAILED", fmt.Sprintf("fetch source overall timeout exceeded after %d bytes", written))
			}
			return written, newCLIError("FWSS_FETCH_FAILED", fmt.Sprintf("failed to stream fetch response body: %s", err.Error()))
		}
		return written, nil
	default:
		return 0, newCLIError("UNSUPPORTED_FETCH_SOURCE", "fetch source scheme is not supported")
	}
}

// inactivityReader wraps an io.Reader and returns an error if no data is
// received within the configured timeout between successive Read calls.
type inactivityReader struct {
	r       io.Reader
	timeout time.Duration
	timer   *time.Timer
}

func (ir *inactivityReader) Read(p []byte) (int, error) {
	type readResult struct {
		n   int
		err error
	}
	ch := make(chan readResult, 1)
	go func() {
		n, err := ir.r.Read(p)
		ch <- readResult{n, err}
	}()

	ir.timer.Reset(ir.timeout)
	select {
	case res := <-ch:
		if !ir.timer.Stop() {
			select {
			case <-ir.timer.C:
			default:
			}
		}
		return res.n, res.err
	case <-ir.timer.C:
		return 0, newCLIError("FWSS_FETCH_FAILED", fmt.Sprintf("fetch stalled: no data received for %s", ir.timeout))
	}
}

func fetchSourceToFile(ctx context.Context, source fetchSource, outputPath string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return 0, newCLIError("FETCH_OUTPUT_WRITE_FAILED", "failed to create fetch output directory")
	}

	tempFile, err := os.CreateTemp(filepath.Dir(outputPath), filepath.Base(outputPath)+".partial-*")
	if err != nil {
		return 0, newCLIError("FETCH_OUTPUT_WRITE_FAILED", "failed to create temporary fetch output")
	}
	tempPath := tempFile.Name()
	cleanup := func() {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
	}

	written, err := copyFetchSource(ctx, source, tempFile)
	if err != nil {
		cleanup()
		return 0, err
	}
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return 0, newCLIError("FETCH_OUTPUT_WRITE_FAILED", "failed to finalize fetched encrypted blob")
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		_ = os.Remove(tempPath)
		return 0, newCLIError("FETCH_OUTPUT_WRITE_FAILED", "failed to publish fetched encrypted blob")
	}
	return written, nil
}

// progressWriter wraps an io.Writer and periodically calls a callback with
// the total bytes written so far. Used by restore-all to show download progress.
type progressWriter struct {
	dst         io.Writer
	written     int64
	interval    time.Duration
	lastReport  time.Time
	onProgress  func(bytesWritten int64)
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.dst.Write(p)
	pw.written += int64(n)
	if now := time.Now(); now.Sub(pw.lastReport) >= pw.interval {
		pw.lastReport = now
		if pw.onProgress != nil {
			pw.onProgress(pw.written)
		}
	}
	return n, err
}

func fetchSourceToFileWithProgress(ctx context.Context, source fetchSource, outputPath string, onProgress func(int64)) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return 0, newCLIError("FETCH_OUTPUT_WRITE_FAILED", "failed to create fetch output directory")
	}

	tempFile, err := os.CreateTemp(filepath.Dir(outputPath), filepath.Base(outputPath)+".partial-*")
	if err != nil {
		return 0, newCLIError("FETCH_OUTPUT_WRITE_FAILED", "failed to create temporary fetch output")
	}
	tempPath := tempFile.Name()
	cleanup := func() {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
	}

	var dst io.Writer = tempFile
	if onProgress != nil {
		dst = &progressWriter{dst: tempFile, interval: 5 * time.Second, lastReport: time.Now(), onProgress: onProgress}
	}
	written, err := copyFetchSource(ctx, source, dst)
	if err != nil {
		cleanup()
		return written, err
	}
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return 0, newCLIError("FETCH_OUTPUT_WRITE_FAILED", "failed to finalize fetched encrypted blob")
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		_ = os.Remove(tempPath)
		return 0, newCLIError("FETCH_OUTPUT_WRITE_FAILED", "failed to publish fetched encrypted blob")
	}
	return written, nil
}

func writeFetchedArtifact(ctx context.Context, outputDir string, doc recoveryMapDocument, selection fetchSelection, signer string, source fetchSource, now time.Time) (fetchedArtifact, error) {
	root := strings.TrimSpace(outputDir)
	if root == "" {
		root = defaultFetchOutputDir
	}

	relativePath := sanitizeFetchRelativePath(selection.file.Name, selection)
	outputPath := filepath.Join(root, sanitizePathSegment(doc.Header.MapID), filepath.FromSlash(relativePath+".enc"))
	bytesWritten, err := fetchSourceToFile(ctx, source, outputPath)
	if err != nil {
		return fetchedArtifact{}, err
	}

	metadataPath := outputPath + ".meta.json"
	metadata := fetchMetadata{
		MapID:       doc.Header.MapID,
		FileID:      strings.TrimSpace(selection.file.FileID),
		VaultOwner:  normalizeAddress(doc.Header.VaultOwner),
		FileName:    selection.file.Name,
		CID:         strings.TrimSpace(selection.file.CID),
		StorageRefs: append([]recoveryMapStorageRef(nil), selection.file.StorageRefs...),
		Signer:      signer,
		FetchSource: source.description,
		FetchedAt:   now.UTC().Format(time.RFC3339Nano),
		OutputKind:  "encrypted_blob",
		ByteLength:  bytesWritten,
	}
	rawMetadata, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fetchedArtifact{}, newCLIError("FETCH_OUTPUT_WRITE_FAILED", "failed to encode fetch metadata")
	}
	if err := os.WriteFile(metadataPath, append(rawMetadata, '\n'), 0o600); err != nil {
		return fetchedArtifact{}, newCLIError("FETCH_OUTPUT_WRITE_FAILED", "failed to write fetch metadata")
	}

	return fetchedArtifact{
		filePath:     outputPath,
		metadataPath: metadataPath,
		bytesWritten: bytesWritten,
	}, nil
}

func sanitizeFetchRelativePath(fileName string, selection fetchSelection) string {
	trimmed := strings.TrimSpace(fileName)
	if trimmed == "" {
		if cid := strings.TrimSpace(selection.file.CID); cid != "" {
			return sanitizePathSegment(cid)
		}
		return fmt.Sprintf("file-%d", selection.index+1)
	}

	cleaned := path.Clean("/" + trimmed)
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" || cleaned == "." {
		return fmt.Sprintf("file-%d", selection.index+1)
	}

	parts := strings.Split(cleaned, "/")
	for index, part := range parts {
		parts[index] = sanitizePathSegment(part)
	}
	relative := path.Join(parts...)
	if strings.HasPrefix(relative, "..") {
		return fmt.Sprintf("file-%d", selection.index+1)
	}
	return relative
}

func sanitizePathSegment(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "unnamed"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_", ":", "_")
	return replacer.Replace(trimmed)
}
