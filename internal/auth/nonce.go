package auth

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

type nonceEntry struct {
	address   string
	expiresAt time.Time
}

// NonceStore issues and atomically consumes single-use authentication challenges.
type NonceStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]nonceEntry
}

// NewNonceStore creates a NonceStore with the given challenge TTL.
func NewNonceStore(ttl time.Duration) *NonceStore {
	return &NonceStore{
		ttl:     ttl,
		entries: make(map[string]nonceEntry),
	}
}

// Issue creates a random 16-byte hex nonce bound to a lowercase 0x address.
func (s *NonceStore) Issue(address string) (string, time.Time, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}
	nonce := hex.EncodeToString(buf)
	exp := time.Now().UTC().Add(s.ttl)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(time.Now().UTC())
	s.entries[nonce] = nonceEntry{
		address:   strings.ToLower(strings.TrimSpace(address)),
		expiresAt: exp,
	}
	return nonce, exp, nil
}

// Consume validates and deletes a nonce so it cannot be replayed.
func (s *NonceStore) Consume(address, nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	s.pruneExpiredLocked(now)

	entry, ok := s.entries[nonce]
	if !ok {
		return false
	}
	delete(s.entries, nonce)

	if now.After(entry.expiresAt) {
		return false
	}
	return entry.address == strings.ToLower(strings.TrimSpace(address))
}

func (s *NonceStore) pruneExpiredLocked(now time.Time) {
	for k, v := range s.entries {
		if now.After(v.expiresAt) {
			delete(s.entries, k)
		}
	}
}
