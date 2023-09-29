package signedattestation

import (
	"context"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/parties"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func VerifyInTotoEnvelope(ctx context.Context, env dsse.Envelope, oidcProvider OIDCProvider) (*intoto.Statement, error) {
	var provider parties.OpenIdProvider
	switch oidcProvider {
	case GithubActionsOIDC:
		var err error
		provider = parties.NewGithubOp("", "")
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unkown oidc provider %v", oidcProvider)
	}

	s, err := dsse.NewEnvelopeVerifier(newOPKSignerVerifier(provider))
	if err != nil {
		return nil, fmt.Errorf("failed to create dsse envelope verifier: %w", err)
	}

	// enforce payload type
	if env.PayloadType != intoto.PayloadType {
		return nil, fmt.Errorf("unsupported payload type %s", env.PayloadType)
	}

	_, err = s.Verify(ctx, &env)
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
