# Signed attestations with OpenPubkey

This library is for signing [in-toto attestations](https://github.com/in-toto/attestation) with [OpenPubkey](https://github.com/openpubkey/openpubkey).

Two functions are provided:

- `SignInTotoStatement` takes an in-toto statement and returns a signed DSSE envelope.
- `VerifyInTotoEnvelope` takes a signed DSSE envelope, verifies the signature, and returns the in-toto statement

That's it!

At the moment only the GitHub Actions OIDC provider is supported.
