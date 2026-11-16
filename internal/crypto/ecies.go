package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/hkdf"
)

const eciesInfo = "rogue-dm-ecies-v1"

// EncryptedPayload is the ECIES wire format shared between Go and Rust (k256 + aes-gcm).
type EncryptedPayload struct {
	V               int    `json:"v"`
	EphemeralPubKey string `json:"ephemeral_pubkey"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

// EncryptECIES encrypts plaintext for recipientPubKeyHex (33-byte compressed secp256k1 hex).
func EncryptECIES(recipientPubKeyHex string, plaintext []byte) (EncryptedPayload, error) {
	recipientPub, err := parseCompressedPubKey(recipientPubKeyHex)
	if err != nil {
		return EncryptedPayload{}, err
	}

	ephemPriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("generate ephemeral key: %w", err)
	}

	aesKey, err := deriveAESKey(ephemPriv, recipientPub)
	if err != nil {
		return EncryptedPayload{}, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return EncryptedPayload{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedPayload{}, err
	}

	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return EncryptedPayload{
		V:               1,
		EphemeralPubKey: "0x" + hex.EncodeToString(ephemPriv.PubKey().SerializeCompressed()),
		Nonce:           "0x" + hex.EncodeToString(nonce),
		Ciphertext:      base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// DecryptECIES decrypts an EncryptedPayload using the recipient's secp256k1 private key.
func DecryptECIES(recipientPriv *secp256k1.PrivateKey, payload EncryptedPayload) ([]byte, error) {
	if payload.V != 1 {
		return nil, fmt.Errorf("unsupported ECIES version: %d", payload.V)
	}
	ephemPub, err := parseCompressedPubKey(payload.EphemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("ephemeral pubkey: %w", err)
	}

	nonce, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(payload.Nonce), "0x"))
	if err != nil || len(nonce) != 12 {
		return nil, fmt.Errorf("invalid AES-GCM nonce")
	}

	ct, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 ciphertext: %w", err)
	}

	aesKey, err := deriveAESKey(recipientPriv, ephemPub)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return plaintext, nil
}

func parseCompressedPubKey(hexStr string) (*secp256k1.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(hexStr), "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode pubkey hex: %w", err)
	}
	pub, err := secp256k1.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 pubkey: %w", err)
	}
	return pub, nil
}

func deriveAESKey(priv *secp256k1.PrivateKey, pub *secp256k1.PublicKey) ([]byte, error) {
	sharedSecret := secp256k1.GenerateSharedSecret(priv, pub)
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte(eciesInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return key, nil
}
