package signedattestation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	rclient "github.com/sigstore/rekor/pkg/client"
)

const (
	DefaultRekorURL = "https://rekor.sigstore.dev"
)

// needed until https://github.com/secure-systems-lab/dsse/pull/61 is merged
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}
type Signature struct {
	KeyID     string    `json:"keyid"`
	Sig       string    `json:"sig"`
	Extension Extension `json:"extension"`
}
type Extension struct {
	Kind string         `json:"kind"`
	Ext  map[string]any `json:"ext"`
}

func uploadTL(ctx context.Context, pkt *pktoken.PKToken, payload []byte, signature []byte, signer crypto.Signer) ([]byte, error) {
	pubCert, err := createX509Cert(pkt, signer)
	if err != nil {
		return nil, fmt.Errorf("Error creating x509 cert: %w", err)
	}

	// generate signature
	hasher := sha256.New()
	hasher.Write(payload)

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

func createX509Cert(pkt *pktoken.PKToken, signer crypto.Signer) ([]byte, error) {
	pkTokenJSON, err := json.Marshal(pkt)
	if err != nil {
		return nil, fmt.Errorf("error marshalling PK token to JSON: %w", err)
	}

	// get subject identitifer from pk token
	var payload struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(pkt.Payload, &payload); err != nil {
		return nil, err
	}

	// encode ephemeral public key
	ecPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("error marshalling public key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:            big.NewInt(1),
		Subject:                 pkix.Name{CommonName: payload.Subject},
		RawSubjectPublicKeyInfo: ecPub,
		NotBefore:               time.Now(),
		NotAfter:                time.Now().Add(365 * 24 * time.Hour), // valid for 1 year
		KeyUsage:                x509.KeyUsageDigitalSignature,
		ExtKeyUsage:             []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid:   true,
		DNSNames:                []string{payload.Subject},
		IsCA:                    false,
		SubjectKeyId:            pkTokenJSON,
	}

	// Create a self-signed X.509 certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("error creating X.509 certificate: %w", err)
	}
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return pem.EncodeToMemory(certBlock), nil
}
