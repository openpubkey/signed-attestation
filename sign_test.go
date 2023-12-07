package signedattestation

import (
	"context"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/client/providers"
)

func TestSignAndVerify(t *testing.T) {
	stmt := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: in_toto.PredicateSPDX,
		},
		Predicate: "test",
	}

	var err error
	provider, err := providers.NewMockOpenIdProvider()
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignInTotoStatement(context.Background(), stmt, provider)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyInTotoEnvelope(context.Background(), env, provider)
	if err != nil {
		t.Fatal(err)
	}
}
