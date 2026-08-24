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

// LocalConnectorResourceID preserves the Local runtime's connector namespace
// contract for resources and cross-connector references.
func LocalConnectorResourceID(connectorID, resourceID string) string {
	return StableID("local_connector_resource", connectorID, resourceID)
}
