package model

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var sloWindowTokenPattern = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)(ms|[smhdw])`)

func NormalizeSLOObjective(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", false
	}
	percent := strings.HasSuffix(value, "%")
	if percent {
		value = strings.TrimSpace(strings.TrimSuffix(value, "%"))
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return "", false
	}
	if percent || parsed > 1 {
		parsed /= 100
	}
	if parsed <= 0 || parsed >= 1 {
		return "", false
	}
	parsed = math.Round(parsed*1e9) / 1e9
	return strconv.FormatFloat(parsed, 'f', -1, 64), true
}

func NormalizeSLOWindow(raw string) (string, time.Duration, bool) {
	value := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), " ", ""))
	if value == "" || strings.HasPrefix(value, "-") {
		return "", 0, false
	}
	if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
		return parsed.String(), parsed, true
	}

	matches := sloWindowTokenPattern.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return "", 0, false
	}
	position := 0
	totalSeconds := float64(0)
	for _, match := range matches {
		if match[0] != position {
			return "", 0, false
		}
		amount, err := strconv.ParseFloat(value[match[2]:match[3]], 64)
		if err != nil || math.IsNaN(amount) || math.IsInf(amount, 0) || amount <= 0 {
			return "", 0, false
		}
		unit := value[match[4]:match[5]]
		switch unit {
		case "ms":
			totalSeconds += amount / 1000
		case "s":
			totalSeconds += amount
		case "m":
			totalSeconds += amount * 60
		case "h":
			totalSeconds += amount * 60 * 60
		case "d":
			totalSeconds += amount * 24 * 60 * 60
		case "w":
			totalSeconds += amount * 7 * 24 * 60 * 60
		}
		position = match[1]
	}
	if position != len(value) || totalSeconds <= 0 || totalSeconds > float64(math.MaxInt64)/float64(time.Second) {
		return "", 0, false
	}
	duration := time.Duration(math.Round(totalSeconds * float64(time.Second)))
	if duration <= 0 {
		return "", 0, false
	}
	return duration.String(), duration, true
}
