package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

var (
	cliVersion   = "dev"
	cliCommit    = "unknown"
	cliBuildDate = "unknown"
)

type cliError struct {
	Code    string
	Message string
}

func (e *cliError) Error() string {
	return e.Code + ": " + e.Message
}

func newCLIError(code string, message string) error {
	return &cliError{Code: code, Message: message}
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin, time.Now().UTC()); err != nil {
		var cliErr *cliError
		if errors.As(err, &cliErr) {
			_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", cliErr.Code, cliErr.Message)
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stderr, "UNEXPECTED: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer, stdin io.Reader, now time.Time) error {
	if len(args) == 0 {
		_, _ = io.WriteString(stdout, helpText())
		return nil
	}

	switch args[0] {
	case "help", "--help", "-h":
		_, _ = io.WriteString(stdout, helpText())
		return nil
	case "version", "--version":
		_, _ = fmt.Fprintf(stdout, "qave-recovery-cli %s\ncommit=%s\nbuild_date=%s\n", cliVersion, cliCommit, cliBuildDate)
		return nil
	case "verify":
		return runVerify(args[1:], stdout, now)
	case "list":
		return runList(args[1:], stdout, now)
	case "unlock":
		return runUnlock(args[1:], stdout, stdin, now)
	case "fetch":
		return runFetch(args[1:], stdout, stdin, now)
	case "decrypt-file":
		return runDecryptFile(args[1:], stdout, stdin, now)
	case "restore-all":
		return runRestoreAll(args[1:], stdout, stdin, now)
	default:
		return newCLIError("USAGE", "unsupported command "+args[0])
	}
}

func helpText() string {
	return fmt.Sprintf(`Qave Recovery Tool

Version: %s
Commit: %s
Build date: %s

Usage:
  qave-recovery-cli verify <map.qrm>
  qave-recovery-cli unlock <map.qrm> --signer <metamask|manual>
  qave-recovery-cli restore-all <map.qrm> --signer <metamask|manual> [--output <name.zip>] [--piece-base-url <url>] [--no-browser]
  qave-recovery-cli fetch <map.qrm> --signer <metamask|manual> --file <name|cid|index>
  qave-recovery-cli decrypt-file --qrm <map.qrm> --file-id <public_id> --ciphertext <path> --output <path> [--signer <metamask|manual>]
  qave-recovery-cli list <map.qrm>
  qave-recovery-cli version

Most users only need:
  1. verify
  2. unlock --signer metamask
  3. restore-all --signer metamask
`, cliVersion, cliCommit, cliBuildDate)
}

func runVerify(args []string, stdout io.Writer, now time.Time) error {
	if len(args) != 1 {
		return newCLIError("USAGE", "verify requires: qave-recovery-cli verify <map.qrm>")
	}

	doc, err := loadRecoveryMap(args[0])
	if err != nil {
		return err
	}
	if err := validateRecoveryMap(doc, now); err != nil {
		return err
	}

	summary := inspectRecoveryPackage(doc, nil)

	_, _ = fmt.Fprintf(stdout, "schema=%s\n", doc.Header.Schema)
	_, _ = fmt.Fprintf(stdout, "map_id=%s\n", doc.Header.MapID)
	_, _ = fmt.Fprintf(stdout, "vault_owner=%s\n", normalizeAddress(doc.Header.VaultOwner))
	_, _ = fmt.Fprintf(stdout, "vault_state_hash=%s\n", doc.Header.VaultStateHash)
	_, _ = fmt.Fprintf(stdout, "generated_at=%s\n", doc.Header.GeneratedAt)
	_, _ = fmt.Fprintf(stdout, "subscription_expires_at=%s\n", doc.Header.SubscriptionExpiresAt)
	_, _ = fmt.Fprintf(stdout, "payload_protection=%s\n", payloadProtectionOf(doc))
	_, _ = fmt.Fprintf(stdout, "signing_scope=%s\n", signingScopeOf(doc))
	_, _ = fmt.Fprintf(stdout, "package_structure=%s\n", summary.Structure)
	if summary.Structure == packageStructureRecoveryPackageV1 {
		_, _ = fmt.Fprintf(stdout, "snapshot_file_count=%d\n", summary.SnapshotFileCount)
		_, _ = fmt.Fprintf(stdout, "fetch_sources_count=%d\n", summary.FetchSourcesCount)
		_, _ = fmt.Fprintf(stdout, "wrapped_keys_count=%d\n", summary.WrappedKeysCount)
		_, _ = fmt.Fprintf(stdout, "wrapped_keys_present=%t\n", summary.WrappedKeysPresent)
		_, _ = fmt.Fprintf(stdout, "recovery_policy_requires_wallet_auth=%t\n", summary.RequiresWalletAuth)
		_, _ = fmt.Fprintf(stdout, "recovery_policy_requires_recovery_key=%t\n", summary.RequiresRecoveryKey)
		_, _ = fmt.Fprintf(stdout, "recovery_policy_recover_all_mode=%s\n", summary.RecoverAllMode)
		_, _ = fmt.Fprintf(stdout, "local_decrypt_required=%t\n", summary.LocalDecryptRequired)
		_, _ = fmt.Fprintf(stdout, "local_package_required=%t\n", summary.LocalPackageRequired)
		_, _ = fmt.Fprintln(stdout, "recover_all_ready=false")
	} else if summary.Structure == packageStructureLockedPayloadUnknown {
		_, _ = fmt.Fprintln(stdout, "recover_all_ready=false")
	}
	switch payloadProtectionOf(doc) {
	case payloadProtectionLegacyPlaintext:
		fileCount := 0
		if doc.Payload != nil {
			fileCount = len(doc.Payload.FileIndex)
		}
		_, _ = fmt.Fprintf(stdout, "file_count=%d\n", fileCount)
	case payloadProtectionWalletBoundEncrypted:
		_, _ = fmt.Fprintf(stdout, "payload_encoding=%s\n", doc.Header.PayloadEncryption.Encoding)
		_, _ = fmt.Fprintln(stdout, "file_count=locked")
	}
	return nil
}

func runList(args []string, stdout io.Writer, now time.Time) error {
	if len(args) != 1 {
		return newCLIError("USAGE", "list requires: qave-recovery-cli list <map.qrm>")
	}

	doc, err := loadRecoveryMap(args[0])
	if err != nil {
		return err
	}
	if err := validateRecoveryMap(doc, now); err != nil {
		return err
	}
	if payloadProtectionOf(doc) == payloadProtectionWalletBoundEncrypted {
		return newCLIError(payloadLockedCode, "payload is wallet-bound encrypted; run unlock first to inspect file_index")
	}

	for _, file := range doc.Payload.FileIndex {
		_, _ = fmt.Fprintf(stdout, "%s\t%d\t%s\t%s\n", file.Name, file.Size, file.Status, file.CID)
	}
	return nil
}

func runUnlock(args []string, stdout io.Writer, stdin io.Reader, now time.Time) error {
	if len(args) < 3 {
		return newCLIError("USAGE", "unlock requires: qave-recovery-cli unlock <map.qrm> --signer <metamask|manual>")
	}
	if args[1] != "--signer" {
		return newCLIError("USAGE", "unlock requires --signer <metamask|manual>")
	}

	path := args[0]
	signer := strings.TrimSpace(strings.ToLower(args[2]))
	if signer != "metamask" && signer != "manual" {
		return newCLIError("UNSUPPORTED_SIGNER", "supported signers are metamask and manual")
	}

	doc, err := loadRecoveryMap(path)
	if err != nil {
		return err
	}
	if err := validateRecoveryMap(doc, now); err != nil {
		return err
	}

	result, err := unlockRecoveryMap(doc, signer, stdout, bufio.NewReader(stdin), now)
	if err != nil {
		return err
	}
	return printUnlockOutcome(stdout, result)
}

type unlockResult struct {
	signer           string
	recoveredAddress string
	doc              recoveryMapDocument
	key              []byte
	payload          recoveryMapPayload
}

func unlockRecoveryMap(doc recoveryMapDocument, signer string, stdout io.Writer, stdin *bufio.Reader, now time.Time) (unlockResult, error) {
	if payloadProtectionOf(doc) == payloadProtectionLegacyPlaintext {
		_, _ = fmt.Fprintf(stdout, "payload_protection=%s\n", payloadProtectionLegacyPlaintext)
		_, _ = fmt.Fprintf(stdout, "challenge_verified=false\n")
		_, _ = fmt.Fprintf(stdout, "payload_unlocked=true\n")
		if doc.Payload == nil {
			return unlockResult{}, newCLIError("QRM_CORRUPTED", "legacy plaintext qrm is missing payload")
		}
		return unlockResult{
			signer:           signer,
			recoveredAddress: doc.Header.VaultOwner,
			doc:              doc,
			payload:          *doc.Payload,
		}, nil
	}

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		return unlockResult{}, err
	}

	_, _ = fmt.Fprintf(stdout, "challenge:\n%s\n", challenge)

	var signature string
	switch signer {
	case "metamask":
		_, _ = fmt.Fprintln(stdout, "signer=metamask")
		bridge, err := startLoopbackBridge(doc, challenge, now, loopbackSessionTTL)
		if err != nil {
			return unlockResult{}, err
		}
		defer func() {
			_ = bridge.Close()
		}()

		signURL := bridge.SignURL()
		_, _ = fmt.Fprintf(stdout, "sign_url=%s\n", signURL)

		if err := openBrowserURL(signURL); err != nil {
			_, _ = fmt.Fprintf(stdout, "Open this URL in your desktop browser: %s\n", signURL)
		} else {
			_, _ = fmt.Fprintf(stdout, "browser_opened=true\n")
			_, _ = fmt.Fprintf(stdout, "If your browser did not open, use this URL: %s\n", signURL)
		}

		callback, err := bridge.WaitForCallback(loopbackSessionTTL)
		if err != nil {
			return unlockResult{}, err
		}
		signature = strings.TrimSpace(callback.Signature)
		recoveredAddress, err := recoverPersonalSignAddress(challenge, signature)
		if err != nil {
			return unlockResult{}, err
		}
		reportedAddress := normalizeAddress(callback.Address)
		if reportedAddress != "" && reportedAddress != recoveredAddress {
			return unlockResult{}, newCLIError("SIGNATURE_INVALID", "reported address does not match recovered signer address")
		}
		if recoveredAddress != normalizeAddress(doc.Header.VaultOwner) {
			return unlockResult{}, newCLIError("WALLET_ADDRESS_MISMATCH", "signature address does not match vault_owner")
		}
		key, err := deriveUnlockKey(doc, challenge, signature)
		if err != nil {
			return unlockResult{}, err
		}
		payload, err := decryptPayload(doc, key)
		if err != nil {
			return unlockResult{}, err
		}
		return unlockResult{
			signer:           signer,
			recoveredAddress: recoveredAddress,
			doc:              doc,
			key:              key,
			payload:          payload,
		}, nil
	case "manual":
		_, _ = fmt.Fprintln(stdout, "signer=manual")
		_, _ = fmt.Fprint(stdout, "paste personal_sign signature: ")
		readSignature, err := stdin.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return unlockResult{}, err
		}
		signature = strings.TrimSpace(readSignature)
		if signature == "" {
			return unlockResult{}, newCLIError("SIGNATURE_REJECTED", "manual signer did not provide a signature")
		}
		recoveredAddress, err := recoverPersonalSignAddress(challenge, signature)
		if err != nil {
			return unlockResult{}, err
		}
		if recoveredAddress != normalizeAddress(doc.Header.VaultOwner) {
			return unlockResult{}, newCLIError("WALLET_ADDRESS_MISMATCH", "signature address does not match vault_owner")
		}
		key, err := deriveUnlockKey(doc, challenge, signature)
		if err != nil {
			return unlockResult{}, err
		}
		payload, err := decryptPayload(doc, key)
		if err != nil {
			return unlockResult{}, err
		}
		return unlockResult{
			signer:           signer,
			recoveredAddress: recoveredAddress,
			doc:              doc,
			key:              key,
			payload:          payload,
		}, nil
	default:
		return unlockResult{}, newCLIError("UNSUPPORTED_SIGNER", "supported signers are metamask and manual")
	}
}

func unlockRecoveryMapWithProvidedSignature(doc recoveryMapDocument, stdout io.Writer, stdin *bufio.Reader, now time.Time, providedSignature string) (unlockResult, error) {
	if payloadProtectionOf(doc) == payloadProtectionLegacyPlaintext {
		_, _ = fmt.Fprintf(stdout, "payload_protection=%s\n", payloadProtectionLegacyPlaintext)
		_, _ = fmt.Fprintf(stdout, "challenge_verified=false\n")
		_, _ = fmt.Fprintf(stdout, "payload_unlocked=true\n")
		if doc.Payload == nil {
			return unlockResult{}, newCLIError("QRM_CORRUPTED", "legacy plaintext qrm is missing payload")
		}
		return unlockResult{
			signer:           "manual",
			recoveredAddress: doc.Header.VaultOwner,
			doc:              doc,
			payload:          *doc.Payload,
		}, nil
	}

	challenge, err := buildUnlockChallenge(doc)
	if err != nil {
		return unlockResult{}, err
	}

	_, _ = fmt.Fprintf(stdout, "challenge:\n%s\n", challenge)
	_, _ = fmt.Fprintln(stdout, "signer=manual")

	signature := strings.TrimSpace(providedSignature)
	if signature == "" {
		return unlockResult{}, newCLIError("SIGNATURE_REJECTED", "manual signer did not provide a signature")
	}

	recoveredAddress, err := recoverPersonalSignAddress(challenge, signature)
	if err != nil {
		return unlockResult{}, err
	}
	if recoveredAddress != normalizeAddress(doc.Header.VaultOwner) {
		return unlockResult{}, newCLIError("WALLET_ADDRESS_MISMATCH", "signature address does not match vault_owner")
	}

	key, err := deriveUnlockKey(doc, challenge, signature)
	if err != nil {
		return unlockResult{}, err
	}
	payload, err := decryptPayload(doc, key)
	if err != nil {
		return unlockResult{}, err
	}

	return unlockResult{
		signer:           "manual",
		recoveredAddress: recoveredAddress,
		doc:              doc,
		key:              key,
		payload:          payload,
	}, nil
}

func printUnlockOutcome(stdout io.Writer, result unlockResult) error {
	summary := inspectRecoveryPackage(result.doc, &result.payload)

	_, _ = fmt.Fprintf(stdout, "wallet_address=%s\n", result.recoveredAddress)
	_, _ = fmt.Fprintf(stdout, "challenge_verified=true\n")
	_, _ = fmt.Fprintf(stdout, "unlock_key_fingerprint=%s\n", fingerprintUnlockKey(result.key))
	_, _ = fmt.Fprintf(stdout, "package_structure=%s\n", summary.Structure)
	if summary.Structure == packageStructureRecoveryPackageV1 {
		_, _ = fmt.Fprintf(stdout, "recovery_policy_requires_recovery_key=%t\n", summary.RequiresRecoveryKey)
		_, _ = fmt.Fprintf(stdout, "recover_all_mode=%s\n", summary.RecoverAllMode)
		_, _ = fmt.Fprintln(stdout, "recover_all_ready=true")
	}

	switch payloadProtectionOf(result.doc) {
	case payloadProtectionLegacyPlaintext:
		_, _ = fmt.Fprintf(stdout, "payload_protection=%s\n", payloadProtectionLegacyPlaintext)
		_, _ = fmt.Fprintf(stdout, "payload_unlocked=true\n")
		_, _ = fmt.Fprintf(stdout, "file_count=%d\n", len(result.payload.FileIndex))
		if summary.Structure == packageStructureRecoveryPackageV1 {
			_, _ = fmt.Fprintln(stdout, "unlock_scope=restore_all_ready")
			_, _ = fmt.Fprintln(stdout, "Unlock complete. Next run restore-all with the same --signer and then enter your Recovery Key.")
		}
		_, _ = fmt.Fprintf(stdout, "Phase 4 complete: payload already legacy plaintext; fetch/decrypt remains pending next phase\n")
		return nil
	case payloadProtectionWalletBoundEncrypted:
		_, _ = fmt.Fprintf(stdout, "payload_protection=%s\n", payloadProtectionWalletBoundEncrypted)
		_, _ = fmt.Fprintf(stdout, "payload_unlocked=true\n")
		_, _ = fmt.Fprintf(stdout, "file_count=%d\n", len(result.payload.FileIndex))
		if summary.Structure == packageStructureRecoveryPackageV1 {
			_, _ = fmt.Fprintln(stdout, "unlock_scope=restore_all_ready")
			_, _ = fmt.Fprintln(stdout, "Unlock complete. Next run restore-all with the same --signer and then enter your Recovery Key.")
		}
		_, _ = fmt.Fprintln(stdout, "Phase 4 complete: wallet-bound payload unlocked; restore-all can now continue the recovery flow")
		return nil
	default:
		return newCLIError("QRM_CORRUPTED", "unknown payload protection mode")
	}
}

func runFetch(args []string, stdout io.Writer, stdin io.Reader, now time.Time) error {
	pathArg, signer, fileSelector, outputDir, pieceBaseURL, err := parseFetchArgs(args)
	if err != nil {
		return err
	}

	doc, err := loadRecoveryMap(pathArg)
	if err != nil {
		return err
	}
	if err := validateRecoveryMap(doc, now); err != nil {
		return err
	}

	result, err := unlockRecoveryMap(doc, signer, stdout, bufio.NewReader(stdin), now)
	if err != nil {
		return err
	}
	summary := inspectRecoveryPackage(result.doc, &result.payload)
	printFetchSemanticPrelude(stdout, summary)

	selection, err := selectRecoveryFile(result.payload, fileSelector)
	if err != nil {
		return err
	}
	source, err := resolveFetchSource(selection.file, pieceBaseURL)
	if err != nil {
		return err
	}

	artifact, err := writeFetchedArtifact(context.Background(), outputDir, result.doc, selection, signer, source, now)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stdout, "wallet_address=%s\n", result.recoveredAddress)
	_, _ = fmt.Fprintf(stdout, "challenge_verified=true\n")
	_, _ = fmt.Fprintf(stdout, "unlock_key_fingerprint=%s\n", fingerprintUnlockKey(result.key))
	_, _ = fmt.Fprintf(stdout, "payload_unlocked=true\n")
	_, _ = fmt.Fprintf(stdout, "selected_file=%s\n", selection.file.Name)
	_, _ = fmt.Fprintf(stdout, "fetch_source=%s\n", source.description)
	_, _ = fmt.Fprintf(stdout, "output_path=%s\n", artifact.filePath)
	_, _ = fmt.Fprintf(stdout, "metadata_path=%s\n", artifact.metadataPath)
	_, _ = fmt.Fprintf(stdout, "fetched_bytes=%d\n", artifact.bytesWritten)
	_, _ = fmt.Fprintln(stdout, "fetch_role=atomic_recovery_primitive")
	_, _ = fmt.Fprintln(stdout, "recover_all_primary_path=true")
	_, _ = fmt.Fprintln(stdout, "Phase 5A complete: encrypted blob fetched; plaintext decrypt remains pending next phase")
	return nil
}

func printFetchSemanticPrelude(stdout io.Writer, summary recoveryPackageSummary) {
	_, _ = fmt.Fprintf(stdout, "package_structure=%s\n", summary.Structure)
	_, _ = fmt.Fprintln(stdout, "fetch_mode=atomic_primitive")
}
