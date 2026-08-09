package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"monicheck/internal/model"
)

const WideRangeQueryAnalyzerID = "builtin.wide_range_query"

const defaultWideRangeQueryThreshold = 24 * time.Hour

type WideRangeQueryAnalyzer struct{}

func NewWideRangeQueryAnalyzer() *WideRangeQueryAnalyzer {
	return &WideRangeQueryAnalyzer{}
}

func (a *WideRangeQueryAnalyzer) ID() string {
	return WideRangeQueryAnalyzerID
}

func (a *WideRangeQueryAnalyzer) Name() string {
	return "Wide Range Query"
}

func (a *WideRangeQueryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *WideRangeQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *WideRangeQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listQueryResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	threshold := durationConfig(analysis.Config, "wide_range_query_threshold", defaultWideRangeQueryThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		query := strings.TrimSpace(resource.Metadata[model.MetadataPromQL])
		if query == "" {
			continue
		}
		duration, ok := maxPromQLRangeDuration(query)
		if !ok || duration <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "WideRangeQuery",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("PromQL max range selector is %s, threshold is %s", duration, threshold),
			},
			Recommendation: "缩短 PromQL range selector，或使用 Recording Rule 预聚合长窗口数据，降低查询延迟和存储扫描成本。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"max_range":   duration.String(),
				"threshold":   threshold.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func maxPromQLRangeDuration(query string) (time.Duration, bool) {
	var maxDuration time.Duration
	var found bool
	runes := []rune(query)
	for i := 0; i < len(runes); i++ {
		if runes[i] != '[' {
			continue
		}
		end := promQLRangeSelectorEnd(runes, i+1)
		if end < 0 {
			continue
		}
		raw := strings.TrimSpace(string(runes[i+1 : end]))
		if colon := strings.Index(raw, ":"); colon >= 0 {
			raw = strings.TrimSpace(raw[:colon])
		}
		duration, ok := parsePromQLDuration(raw)
		if ok && duration > maxDuration {
			maxDuration = duration
			found = true
		}
		i = end
	}
	return maxDuration, found
}

func promQLRangeSelectorEnd(runes []rune, start int) int {
	for i := start; i < len(runes); i++ {
		if runes[i] == ']' {
			return i
		}
		if runes[i] == '"' || runes[i] == '\'' || runes[i] == '`' {
			return -1
		}
	}
	return -1
}

func parsePromQLDuration(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	var total time.Duration
	runes := []rune(value)
	for i := 0; i < len(runes); {
		if !unicode.IsDigit(runes[i]) {
			return 0, false
		}
		start := i
		for i < len(runes) && unicode.IsDigit(runes[i]) {
			i++
		}
		amount, err := strconv.Atoi(string(runes[start:i]))
		if err != nil || amount <= 0 || i >= len(runes) {
			return 0, false
		}
		unitStart := i
		for i < len(runes) && unicode.IsLetter(runes[i]) {
			i++
		}
		unit := string(runes[unitStart:i])
		multiplier, ok := promQLDurationUnit(unit)
		if !ok {
			return 0, false
		}
		total += time.Duration(amount) * multiplier
	}
	return total, total > 0
}

func promQLDurationUnit(unit string) (time.Duration, bool) {
	switch unit {
	case "s":
		return time.Second, true
	case "m":
		return time.Minute, true
	case "h":
		return time.Hour, true
	case "d":
		return 24 * time.Hour, true
	case "w":
		return 7 * 24 * time.Hour, true
	case "y":
		return 365 * 24 * time.Hour, true
	default:
		return 0, false
	}
}
