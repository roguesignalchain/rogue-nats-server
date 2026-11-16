package auth_test

import (
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/roguesignalchain/rogue-nats-server/internal/auth"
)

func TestEIP191SignAndVerify(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	addr := auth.PubKeyToAddress(priv.PubKey())
	msg := auth.BuildChallengeMessage(800055, addr, "abc123")

	sig, err := auth.SignPersonalMessage(priv, msg)
	if err != nil {
		t.Fatalf("SignPersonalMessage: %v", err)
	}

	pubHex, err := auth.VerifyPersonalSignature(addr, msg, sig)
	if err != nil {
		t.Fatalf("VerifyPersonalSignature: %v", err)
	}
	if len(pubHex) != 68 { // "0x" + 33 bytes compressed hex
		t.Fatalf("unexpected compressed pubkey hex length: %d (%s)", len(pubHex), pubHex)
	}

	if _, err := auth.VerifyPersonalSignature("0x0000000000000000000000000000000000000001", msg, sig); err == nil {
		t.Fatal("expected mismatch error for wrong address")
	}
	if _, err := auth.VerifyPersonalSignature(addr, msg+"tampered", sig); err == nil {
		t.Fatal("expected mismatch error for tampered message")
	}
}

func TestNonceStoreSingleUseAndTTL(t *testing.T) {
	ns := auth.NewNonceStore(50 * time.Millisecond)
	addr := "0xe9aaE535B7971A9AC8C6af0e4B524D02260D3a03"

	nonce, _, err := ns.Issue(addr)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !ns.Consume(addr, nonce) {
		t.Fatal("expected first Consume to succeed")
	}
	if ns.Consume(addr, nonce) {
		t.Fatal("expected replay Consume to fail")
	}

	nonce2, _, err := ns.Issue(addr)
	if err != nil {
		t.Fatalf("Issue 2: %v", err)
	}
	time.Sleep(70 * time.Millisecond)
	if ns.Consume(addr, nonce2) {
		t.Fatal("expected expired nonce Consume to fail")
	}
}
