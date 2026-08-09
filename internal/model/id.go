package model

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

func StableID(parts ...string) string {
	hash := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(hash[:])
}
