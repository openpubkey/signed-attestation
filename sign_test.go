package signedattestation

import (
	"context"
	"crypto"
	"fmt"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/pktoken"
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

func TestSignAndVerifyExt(t *testing.T) {
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

	tl := &MockTL{
		UploadLogEntryFunc: func(ctx context.Context, pkToken *pktoken.PKToken, payload []byte, signature []byte, signer crypto.Signer) ([]byte, error) {
			return []byte(""), nil
		},
		VerifyLogEntryFunc: func(entryBytes []byte) error {
			return nil
		},
	}
	// uncomment to test with Rekor TL
	// tl := &RekorTL{}

	ctx := context.WithValue(context.Background(), tlCtxKey(DefaultCtxKey), tl)
	env, err := SignInTotoStatementExt(ctx, stmt, provider)
	if err != nil {
		t.Fatal(err)
	}

	verStmt, err := VerifyInTotoEnvelopeExt(ctx, env, provider)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Print(verStmt)
}
