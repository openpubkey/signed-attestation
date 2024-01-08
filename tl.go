package signedattestation

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/openpubkey/openpubkey/cert"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	rclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

const (
	DefaultRekorURL = "https://rekor.sigstore.dev"
	DefaultCtxKey   = "tl"
)

type tlCtxKeyType struct{}

var TlCtxKey tlCtxKeyType

// sets TL in context
func WithTL(ctx context.Context, tl TL) context.Context {
	return context.WithValue(ctx, TlCtxKey, tl)
}

// gets TL from context, defaults to Rekor TL if not set
func GetTL(ctx context.Context) TL {
	t, ok := ctx.Value(TlCtxKey).(TL)
	if !ok {
		t = &RekorTL{}
	}
	return t
}

type TlPayload struct {
	Algorithm string
	Hash      string
	Signature string
	PublicKey string
}

type TL interface {
	UploadLogEntry(ctx context.Context, pkToken *pktoken.PKToken, payload, signature []byte, signer crypto.Signer) ([]byte, error)
	VerifyLogEntry(ctx context.Context, entryBytes []byte) error
	VerifyEntryPayload(entryBytes, payload, pkToken []byte) error
}

type MockTL struct {
	UploadLogEntryFunc     func(ctx context.Context, pkToken *pktoken.PKToken, payload, signature []byte, signer crypto.Signer) ([]byte, error)
	VerifyLogEntryFunc     func(ctx context.Context, entryBytes []byte) error
	VerifyEntryPayloadFunc func(entryBytes, payload, pkToken []byte) error
}

func (tl *MockTL) UploadLogEntry(ctx context.Context, pkToken *pktoken.PKToken, payload, signature []byte, signer crypto.Signer) ([]byte, error) {
	if tl.UploadLogEntryFunc != nil {
		return tl.UploadLogEntryFunc(ctx, pkToken, payload, signature, signer)
	}
	return nil, nil
}

func (tl *MockTL) VerifyLogEntry(ctx context.Context, entryBytes []byte) error {
	if tl.VerifyLogEntryFunc != nil {
		return tl.VerifyLogEntryFunc(ctx, entryBytes)
	}
	return nil
}

func (tl *MockTL) VerifyEntryPayload(entryBytes, payload, pkToken []byte) error {
	if tl.VerifyLogEntryFunc != nil {
		return tl.VerifyEntryPayloadFunc(entryBytes, payload, pkToken)
	}
	return nil
}

type RekorTL struct{}

// UploadLogEntry submits a PK token signature to the transparency log
func (tl *RekorTL) UploadLogEntry(ctx context.Context, pkToken *pktoken.PKToken, payload, signature []byte, signer crypto.Signer) ([]byte, error) {
	// generate self-signed x509 cert to wrap PK token
	pubCert, err := cert.CreateX509Cert(pkToken, signer)
	if err != nil {
		return nil, fmt.Errorf("Error creating x509 cert: %w", err)
	}

	// generate hash of payload
	hasher := sha256.New()
	hasher.Write(payload)

	// upload entry
	rekorClient, err := rclient.GetRekorClient(DefaultRekorURL)
	if err != nil {
		return nil, fmt.Errorf("Error creating rekor client: %w", err)
	}
	entry, err := cosign.TLogUpload(ctx, rekorClient, signature, hasher, pubCert)
	if err != nil {
		return nil, fmt.Errorf("Error uploading tlog: %w", err)
	}
	entryBytes, err := entry.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("error marshalling TL entry: %w", err)
	}
	return entryBytes, nil
}

// VerifyLogEntry verifies a transparency log entry
func (tl *RekorTL) VerifyLogEntry(ctx context.Context, entryBytes []byte) error {
	entry := new(models.LogEntryAnon)
	err := entry.UnmarshalBinary(entryBytes)
	if err != nil {
		return fmt.Errorf("error failed to unmarshal TL entry: %w", err)
	}
	err = entry.Verification.Validate(strfmt.Default)
	if err != nil {
		return fmt.Errorf("TL entry failed validation: %w", err)
	}

	rekorPubKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return fmt.Errorf("error failed to get rekor public keys")
	}
	err = cosign.VerifyTLogEntryOffline(ctx, entry, rekorPubKeys)
	if err != nil {
		return fmt.Errorf("TL entry failed verification: %w", err)
	}
	return nil
}

func (tl *RekorTL) VerifyEntryPayload(entryBytes, payload, pkToken []byte) error {
	// check that TL entry payload matches envelope payload
	entry := new(models.LogEntryAnon)
	err := entry.UnmarshalBinary(entryBytes)
	if err != nil {
		return fmt.Errorf("error failed to unmarshal TL entry: %w", err)
	}
	rekord, err := extractHashedRekord(entry.Body.(string))
	if err != nil {
		return fmt.Errorf("error extract HashedRekord from TL entry: %w", err)
	}

	// compare payload hashes
	payloadHash := hex.EncodeToString(s256(payload))
	if rekord.Hash != payloadHash {
		return fmt.Errorf("error payload and tl entry hash mismatch")
	}

	// compare pk tokens
	cert, err := base64.StdEncoding.DecodeString(rekord.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}
	p, _ := pem.Decode(cert)
	result, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	if string(result.SubjectKeyId) != string(pkToken) {
		return fmt.Errorf("error payload and tl entry pktoken mismatch")
	}
	return nil
}

func extractHashedRekord(Body string) (*TlPayload, error) {
	sig := new(TlPayload)
	pe, err := models.UnmarshalProposedEntry(base64.NewDecoder(base64.StdEncoding, strings.NewReader(Body)), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	impl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}
	switch entry := impl.(type) {
	case *hashedrekord_v001.V001Entry:
		sig.Algorithm = *entry.HashedRekordObj.Data.Hash.Algorithm
		sig.Hash = *entry.HashedRekordObj.Data.Hash.Value
		sig.Signature = entry.HashedRekordObj.Signature.Content.String()
		sig.PublicKey = entry.HashedRekordObj.Signature.PublicKey.Content.String()
		return sig, nil
	default:
		return nil, errors.New("unsupported type")
	}
}
