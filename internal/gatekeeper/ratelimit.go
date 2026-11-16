package gatekeeper

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter enforces per-address message and control-command rate limits scaled by MinerLevel.
type RateLimiter struct {
	mu      sync.Mutex
	msgLim  map[string]*rate.Limiter
	roomLim map[string]*rate.Limiter
}

// NewRateLimiter creates a per-address rate limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		msgLim:  make(map[string]*rate.Limiter),
		roomLim: make(map[string]*rate.Limiter),
	}
}

// AllowMessage checks if addr is within its message/DM rate budget for its MinerLevel.
func (rl *RateLimiter) AllowMessage(addr string, level uint32, isAdmin bool) bool {
	if isAdmin {
		return true
	}
	rl.mu.Lock()
	lim, ok := rl.msgLim[addr]
	if !ok {
		perMin, burst := messageQuotaForLevel(level)
		lim = rate.NewLimiter(rate.Every(time.Minute/time.Duration(perMin)), burst)
		rl.msgLim[addr] = lim
	}
	rl.mu.Unlock()
	return lim.Allow()
}

// AllowCreateRoom enforces 1 room creation every 5 minutes for non-admin addresses.
func (rl *RateLimiter) AllowCreateRoom(addr string, isAdmin bool) bool {
	if isAdmin {
		return true
	}
	rl.mu.Lock()
	lim, ok := rl.roomLim[addr]
	if !ok {
		lim = rate.NewLimiter(rate.Every(5*time.Minute), 1)
		rl.roomLim[addr] = lim
	}
	rl.mu.Unlock()
	return lim.Allow()
}

func messageQuotaForLevel(level uint32) (perMin int, burst int) {
	switch {
	case level >= 3:
		return 30, 10
	case level >= 1:
		return 15, 5
	default:
		return 6, 3
	}
}
