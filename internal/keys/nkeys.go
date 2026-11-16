package keys

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nkeys"
)

// OperatorKeys holds the persistent NKey pairs used by the embedded NATS account
// and the Auth Callout signing service.
type OperatorKeys struct {
	AccountKP      nkeys.KeyPair
	AccountPub     string
	AuthCalloutKP  nkeys.KeyPair
	AuthCalloutPub string
}

// LoadOrCreate loads existing NKey seeds from keysDir or generates new ones on first boot.
func LoadOrCreate(keysDir string) (*OperatorKeys, error) {
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("create keys directory: %w", err)
	}

	accountKP, accountPub, err := loadOrCreatePair(
		filepath.Join(keysDir, "account.nk"),
		filepath.Join(keysDir, "account.pub"),
		nkeys.CreateAccount,
	)
	if err != nil {
		return nil, fmt.Errorf("account nkey: %w", err)
	}

	calloutKP, calloutPub, err := loadOrCreatePair(
		filepath.Join(keysDir, "auth_callout.nk"),
		filepath.Join(keysDir, "auth_callout.pub"),
		nkeys.CreateUser,
	)
	if err != nil {
		return nil, fmt.Errorf("auth callout nkey: %w", err)
	}

	return &OperatorKeys{
		AccountKP:      accountKP,
		AccountPub:     accountPub,
		AuthCalloutKP:  calloutKP,
		AuthCalloutPub: calloutPub,
	}, nil
}

func loadOrCreatePair(seedPath, pubPath string, createFn func() (nkeys.KeyPair, error)) (nkeys.KeyPair, string, error) {
	rawSeed, err := os.ReadFile(seedPath)
	if err == nil {
		kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(string(rawSeed))))
		if err != nil {
			return nil, "", fmt.Errorf("parse existing seed %s: %w", seedPath, err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			return nil, "", fmt.Errorf("extract public key %s: %w", seedPath, err)
		}
		return kp, pub, nil
	}
	if !os.IsNotExist(err) {
		return nil, "", fmt.Errorf("read seed %s: %w", seedPath, err)
	}

	kp, err := createFn()
	if err != nil {
		return nil, "", fmt.Errorf("generate nkey: %w", err)
	}
	seed, err := kp.Seed()
	if err != nil {
		return nil, "", fmt.Errorf("extract seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, "", fmt.Errorf("extract public key: %w", err)
	}

	if err := os.WriteFile(seedPath, seed, 0o600); err != nil {
		return nil, "", fmt.Errorf("write seed %s: %w", seedPath, err)
	}
	if err := os.WriteFile(pubPath, []byte(pub+"\n"), 0o644); err != nil {
		return nil, "", fmt.Errorf("write public key %s: %w", pubPath, err)
	}
	return kp, pub, nil
}
