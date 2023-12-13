package signedattestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
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
	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}

	env := new(Envelope)
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	env.PayloadType = intoto.PayloadType

	paeEnc := dsse.PAE(intoto.PayloadType, payload)

	hash := s256(paeEnc)
	hashHex := hex.EncodeToString(hash)

	signer, err := util.GenKeyPair(jwa.ES256)
	if err != nil {
		return nil, fmt.Errorf("error generating key pair: %w", err)
	}

	opkClient := client.OpkClient{Op: provider}
	pkToken, err := opkClient.OidcAuth(ctx, signer, jwa.ES256, map[string]any{"att": hashHex}, true)
	if err != nil {
		return nil, fmt.Errorf("error getting PK token: %w", err)
	}

	pkTokenJSON, err := json.Marshal(pkToken)
	if err != nil {
		return nil, fmt.Errorf("error marshalling PK token to JSON: %w", err)
	}

	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	pubKey := signer.Public().(*ecdsa.PublicKey)
	pubBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
	keyID := s256(pubBytes)

	// upload to TL
	entry, err := uploadTL(ctx, "test", pkTokenJSON, paeEnc, sig, signer)
	if err != nil {
		return nil, fmt.Errorf("error uploading TL entry: %w", err)
	}

	// add signature w/ ext to dsse envelope
	env.Signatures = append(env.Signatures, Signature{
		KeyID: hex.EncodeToString(keyID),
		Sig:   base64.StdEncoding.EncodeToString(sig),
		Extension: Extension{
			Kind: "OPK",
			Ext: map[string]any{
				"pkt": pkTokenJSON,
				"tl":  entry.Body,
			},
		},
	})

	return env, nil
}
