// Package batchsig provides an abstraction for batch verifying public
// key signatures.
package batchsig

import (
	"fmt"

	"github.com/oasisprotocol/ed25519"

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
		edPubKey, ok := pubKeys[i].(tmEd25519.PubKey)
		if !ok {
			return verifyBatchFallback(pubKeys, msgs, sigs)
		}

		nativePubKeys = append(nativePubKeys, ed25519.PublicKey(edPubKey[:]))
	}
	_, validSigs, err := ed25519.VerifyBatch(nil, nativePubKeys, msgs, sigs, &defaultOptions)
	return validSigs, err
}

func verifyBatchFallback(pubKeys []crypto.PubKey, msgs, sigs [][]byte) ([]bool, error) {
	validSigs := make([]bool, len(pubKeys))
	for i := range pubKeys {
		validSigs[i] = pubKeys[i].VerifySignature(msgs[i], sigs[i])
	}
	return validSigs, nil
}
