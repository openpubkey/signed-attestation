package signedattestation

import (
	"context"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/client"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func VerifyInTotoEnvelope(ctx context.Context, env *dsse.Envelope, provider client.OpenIdProvider) (*intoto.Statement, error) {

	s, err := dsse.NewEnvelopeVerifier(NewOPKSignerVerifier(provider))
	if err != nil {
		return nil, fmt.Errorf("failed to create dsse envelope verifier: %w", err)
	}

	// enforce payload type
	if env.PayloadType != intoto.PayloadType {
		return nil, fmt.Errorf("unsupported payload type %s", env.PayloadType)
	}

	_, err = s.Verify(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("failed to verify dsse envelope: %w", err)
	}

	stmt := new(intoto.Statement)
	stmtBytes, err := env.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("failed to decode in-toto statement: %w", err)
	}
	err = json.Unmarshal(stmtBytes, stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}

	return stmt, nil
}
