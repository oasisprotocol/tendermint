// Package batchsig provides an abstraction for batch verifying public
// key signatures.
package batchsig

import (
	"fmt"

	"github.com/oasislabs/ed25519"

	"github.com/tendermint/tendermint/crypto"
	tmEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
)

var defaultOptions ed25519.Options

// VerifyBatch verifies signatures in bulk.  Note that this call is only
// faster than calling VerifyBytes for each signature iff every signature
// is valid.
func VerifyBatch(pubKeys []crypto.PubKey, msgs, sigs [][]byte) ([]bool, error) {
	if len(pubKeys) != len(msgs) || len(msgs) != len(sigs) {
		return nil, fmt.Errorf("tendermint/crypto/ed25519: parameter size mismatch")
	}

	// Currently only Ed25519 supports batch verification.
	nativePubKeys := make([]ed25519.PublicKey, 0, len(pubKeys))
	for i := range pubKeys {
		edPubKey, ok := pubKeys[i].(tmEd25519.PubKeyEd25519)
		if !ok || len(sigs[i]) != ed25519.SignatureSize {
			// The batch verify will fail if:
			//  * The signature algorithm isn't actually Ed25519.
			//  * The signature is malformed (not 64 bytes).
			//
			// The latter could be changed, since Oasis Labs is
			// the upstream, but it would just switch to the
			// internal sequential verification code anyway.
			return verifyBatchFallback(pubKeys, msgs, sigs)
		}

		nativePubKeys = append(nativePubKeys, ed25519.PublicKey(edPubKey[:]))
	}

	var (
		validSigs []bool
		err       error
	)
	if tmEd25519.OasisDomainSeparationEnabled() {
		validSigs, err = tmEd25519.OasisVerifyBatchContext(nativePubKeys, msgs, sigs)
	} else {
		_, validSigs, err = ed25519.VerifyBatch(nil, nativePubKeys, msgs, sigs, &defaultOptions)
	}
	return validSigs, err
}

func verifyBatchFallback(pubKeys []crypto.PubKey, msgs, sigs [][]byte) ([]bool, error) {
	validSigs := make([]bool, len(pubKeys))
	for i := range pubKeys {
		validSigs[i] = pubKeys[i].VerifyBytes(msgs[i], sigs[i])
	}
	return validSigs, nil
}
