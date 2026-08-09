package analyzer

import (
	"strconv"
	"strings"
	"time"
)

func intConfig(config map[string]any, key string, fallback int) int {
	value, ok := config[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		if typed > 0 {
			return typed
		}
	case int64:
		if typed > 0 {
			return int(typed)
		}
	case float64:
		if typed > 0 {
			return int(typed)
		}
	case string:
		parsed, err := strconv.Atoi(typed)
		if err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func floatConfig(config map[string]any, key string, fallback float64) float64 {
	value, ok := config[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		if typed > 0 {
			return float64(typed)
		}
	case int64:
		if typed > 0 {
			return float64(typed)
		}
	case float64:
		if typed > 0 {
			return typed
		}
	case string:
		parsed, err := strconv.ParseFloat(typed, 64)
		if err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func durationConfig(config map[string]any, key string, fallback time.Duration) time.Duration {
	value, ok := config[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case time.Duration:
		if typed > 0 {
			return typed
		}
	case string:
		parsed, err := time.ParseDuration(typed)
		if err == nil && parsed > 0 {
			return parsed
		}
	case int:
		if typed > 0 {
			return time.Duration(typed)
		}
	case int64:
		if typed > 0 {
			return time.Duration(typed)
		}
	case float64:
		if typed > 0 {
			return time.Duration(typed)
		}
	}
	return fallback
}

func stringSliceConfig(config map[string]any, key string, fallback []string) []string {
	value, ok := config[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case []string:
		return cleanStrings(typed)
	case []any:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			if value, ok := item.(string); ok {
				items = append(items, value)
			}
		}
		return cleanStrings(items)
	case string:
		if strings.TrimSpace(typed) == "" {
			return fallback
		}
		return cleanStrings(strings.Split(typed, ","))
	}
	return fallback
}

func cleanStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		cleaned = append(cleaned, value)
	}
	return cleaned
}
