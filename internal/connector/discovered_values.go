package connector

import (
	"strings"

	"monicheck/internal/model"
)

type discoveredValue struct {
	raw         string
	fingerprint string
}

func privacySafeDiscoveredValues(system string, key string, values []string) []discoveredValue {
	result := make([]discoveredValue, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		fingerprint := model.StableID("discovered-value", system, key, value)
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		result = append(result, discoveredValue{raw: value, fingerprint: fingerprint})
	}
	return result
}

func redactedDiscoveredValueName(key string, fingerprint string) string {
	const displayLength = 12
	if len(fingerprint) > displayLength {
		fingerprint = fingerprint[:displayLength]
	}
	return strings.TrimSpace(key) + "=<redacted:" + fingerprint + ">"
}
