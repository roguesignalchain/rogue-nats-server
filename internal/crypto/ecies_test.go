package crypto_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	rcrypto "github.com/roguesignalchain/rogue-nats-server/internal/crypto"
)

func TestECIESRoundTripAndWrongKeyRejection(t *testing.T) {
	alicePriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey alice: %v", err)
	}
	bobPriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey bob: %v", err)
	}

	bobPubHex := "0x" + hex.EncodeToString(bobPriv.PubKey().SerializeCompressed())
	secretMsg := []byte("Encrypted Rogue Signal DM payload #1")

	enc, err := rcrypto.EncryptECIES(bobPubHex, secretMsg)
	if err != nil {
		t.Fatalf("EncryptECIES: %v", err)
	}

	dec, err := rcrypto.DecryptECIES(bobPriv, enc)
	if err != nil {
		t.Fatalf("DecryptECIES: %v", err)
	}
	if !bytes.Equal(dec, secretMsg) {
		t.Fatalf("decrypted mismatch: got %q, want %q", dec, secretMsg)
	}

	if _, err := rcrypto.DecryptECIES(alicePriv, enc); err == nil {
		t.Fatal("expected decryption with wrong private key to fail")
	}
}
