package auth

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// BuildChallengeMessage returns the deterministic EIP-191 message signed by clients and agents.
func BuildChallengeMessage(chainID uint64, address, nonce string) string {
	return fmt.Sprintf(
		"Rogue Signal Messaging Auth\nChainID: %d\nAddress: %s\nNonce: %s",
		chainID,
		strings.ToLower(strings.TrimSpace(address)),
		nonce,
	)
}

// PubKeyToAddress derives the lowercase 0x Ethereum/Rogue address from a secp256k1 public key.
func PubKeyToAddress(pub *secp256k1.PublicKey) string {
	uncompressed := pub.SerializeUncompressed() // 65 bytes: 0x04 || X(32) || Y(32)
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	digest := h.Sum(nil)
	return "0x" + hex.EncodeToString(digest[12:])
}

// SignPersonalMessage signs a message using EIP-191 personal_sign format (65-byte [R||S||V]).
func SignPersonalMessage(priv *secp256k1.PrivateKey, message string) (string, error) {
	digest := eip191Digest(message)
	// SignCompact returns [V_compact(1) || R(32) || S(32)] where V_compact = 27 + recoveryID.
	compact := ecdsa.SignCompact(priv, digest, false)
	if len(compact) != 65 {
		return "", fmt.Errorf("unexpected compact signature length: %d", len(compact))
	}
	// Convert to standard Ethereum [R(32) || S(32) || V(1)].
	ethSig := make([]byte, 65)
	copy(ethSig[0:64], compact[1:65])
	ethSig[64] = compact[0]
	return "0x" + hex.EncodeToString(ethSig), nil
}

// VerifyPersonalSignature recovers the secp256k1 public key from an EIP-191 signature
// and verifies it matches expectedAddress. Returns the compressed public key hex (0x...).
func VerifyPersonalSignature(expectedAddress, message, sigHex string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(sigHex), "0x"))
	if err != nil || len(raw) != 65 {
		return "", fmt.Errorf("invalid signature format")
	}

	v := raw[64]
	if v == 0 || v == 1 {
		v += 27
	}
	if v != 27 && v != 28 {
		return "", fmt.Errorf("invalid recovery byte: %d", raw[64])
	}

	// dcrd RecoverCompact expects [V_compact(1) || R(32) || S(32)].
	compact := make([]byte, 65)
	compact[0] = v
	copy(compact[1:65], raw[0:64])

	digest := eip191Digest(message)
	pub, _, err := ecdsa.RecoverCompact(compact, digest)
	if err != nil {
		return "", fmt.Errorf("ecrecover failed: %w", err)
	}

	recovered := PubKeyToAddress(pub)
	if !strings.EqualFold(recovered, strings.TrimSpace(expectedAddress)) {
		return "", fmt.Errorf("signature address mismatch: recovered %s, expected %s", recovered, expectedAddress)
	}

	return "0x" + hex.EncodeToString(pub.SerializeCompressed()), nil
}

func eip191Digest(message string) []byte {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(prefix))
	h.Write([]byte(message))
	return h.Sum(nil)
}
