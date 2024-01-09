package signedattestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/util"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// the following types are needed until https://github.com/secure-systems-lab/dsse/pull/61 is merged
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

func SignInTotoStatement(ctx context.Context, stmt intoto.Statement, provider client.OpenIdProvider) (*dsse.Envelope, error) {
	s, err := dsse.NewEnvelopeSigner(NewOPKSignerVerifier(provider))
	if err != nil {
		return nil, fmt.Errorf("error creating dsse signer: %w", err)
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}

	env, err := s.SignPayload(ctx, intoto.PayloadType, payload)
	if err != nil {
		return nil, err
	}

	return env, nil
}

func SignInTotoStatementExt(ctx context.Context, stmt intoto.Statement, provider client.OpenIdProvider) (*Envelope, error) {
	tl := GetTL(ctx)

	// encode in-toto statement
	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	env := new(Envelope)
	env.Payload = base64.StdEncoding.Strict().EncodeToString(payload)
	env.PayloadType = intoto.PayloadType
	encPayload := dsse.PAE(intoto.PayloadType, payload)

	// statement message digest
	hash := s256(encPayload)
	hashHex := hex.EncodeToString(hash)

	// generate ephemeral keys to sign message digest
	signer, err := util.GenKeyPair(jwa.ES256)
	if err != nil {
		return nil, fmt.Errorf("error generating key pair: %w", err)
	}
	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	ecPub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting signer to ecdsa public key")
	}
	pub, err := x509.MarshalPKIXPublicKey(ecPub)
	if err != nil {
		return nil, fmt.Errorf("error marshalling public key: %w", err)
	}
	keyID := s256(pub)

	// generate pk token with message digest and ephemeral signing keys
	opkClient := client.OpkClient{Op: provider}
	pkToken, err := opkClient.OidcAuth(ctx, signer, jwa.ES256, map[string]any{"att": hashHex}, true)
	if err != nil {
		return nil, fmt.Errorf("error getting PK token: %w", err)
	}
	pkTokenJSON, err := json.Marshal(pkToken)
	if err != nil {
		return nil, fmt.Errorf("error marshalling PK token to JSON: %w", err)
	}

	// upload to TL
	entry, err := tl.UploadLogEntry(ctx, pkToken, encPayload, sig, signer)
	if err != nil {
		return nil, fmt.Errorf("error uploading TL entry: %w", err)
	}
	entryStr := base64.StdEncoding.Strict().EncodeToString(entry)

	// add signature w/ opk extension to dsse envelope
	env.Signatures = append(env.Signatures, Signature{
		KeyID: hex.EncodeToString(keyID),                       // ephemeral public key ID
		Sig:   base64.StdEncoding.Strict().EncodeToString(sig), // ECDSA signature using ephemeral keys
		Extension: Extension{
			Kind: OpkSignatureID,
			Ext: map[string]any{
				"pkt": pkTokenJSON, // PK token + GQ signature
				"tl":  entryStr,    // transparency log entry metadata
			},
		},
	})

	return env, nil
}
