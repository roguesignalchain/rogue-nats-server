package gatekeeper

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxMessageRunes enforces the 2000-character limit per chat message.
	MaxMessageRunes = 2000
	// MaxTopicRunes enforces a clean channel topic length.
	MaxTopicRunes = 200
)

var (
	roomNameRegex = regexp.MustCompile(`^[a-z0-9-]{2,32}$`)
	urlDetectRe   = regexp.MustCompile(`(?i)(https?://|www\.|javascript:|data:|\]\(https?://)`)
	httpInsecure  = regexp.MustCompile(`(?i)\bhttp://`)
	badSchemes    = regexp.MustCompile(`(?i)\b(javascript|data):`)
)

// ValidateRoomName ensures room names cannot inject NATS wildcards (., *, >) or whitespace.
func ValidateRoomName(name string) error {
	if !roomNameRegex.MatchString(name) {
		return fmt.Errorf("room name must match ^[a-z0-9-]{2,32}$")
	}
	return nil
}

// SanitizeAndValidateText checks length <= 2000 runes and rejects null bytes, ANSI escapes, and unsafe control chars.
func SanitizeAndValidateText(text string) (string, error) {
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("message text cannot be empty")
	}
	if utf8.RuneCountInString(text) > MaxMessageRunes {
		return "", fmt.Errorf("message exceeds %d characters", MaxMessageRunes)
	}
	for _, r := range text {
		if r == 0 || r == 0x1b {
			return "", fmt.Errorf("message contains forbidden control or ANSI escape characters")
		}
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return "", fmt.Errorf("message contains forbidden control character")
		}
	}
	return text, nil
}

// InspectLinks checks if the text contains URLs and blocks insecure http:// or script/data schemes.
func InspectLinks(text string) (hasLink bool, err error) {
	if badSchemes.MatchString(text) {
		return true, fmt.Errorf("forbidden URI scheme in message")
	}
	if httpInsecure.MatchString(text) {
		return true, fmt.Errorf("only https:// links are permitted")
	}
	if urlDetectRe.MatchString(text) {
		return true, nil
	}
	return false, nil
}
