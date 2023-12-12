package signedattestation

import (
	"context"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/client"

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

	// upload to TL

	// add LogID + signedEntryTimestamp to DSSE envelope

	return env, nil
}
