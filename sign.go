package signedattestation

import (
	"context"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/parties"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func SignInTotoStatement(ctx context.Context, stmt intoto.Statement, oidcProvider OIDCProvider) (*dsse.Envelope, error) {
	var provider parties.OpenIdProvider
	switch oidcProvider {
	case GithubActionsOIDC:
		var err error
		provider, err = parties.NewGithubOpFromEnvironment()
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unkown oidc provider %v", oidcProvider)
	}

	s, err := dsse.NewEnvelopeSigner(newOPKSignerVerifier(provider))
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
