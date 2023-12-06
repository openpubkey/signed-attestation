package signedattestation

import (
	"context"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/client"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

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
