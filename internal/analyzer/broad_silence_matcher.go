package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const BroadSilenceMatcherAnalyzerID = "builtin.broad_silence_matcher"

type BroadSilenceMatcherAnalyzer struct{}

func NewBroadSilenceMatcherAnalyzer() *BroadSilenceMatcherAnalyzer {
	return &BroadSilenceMatcherAnalyzer{}
}

func (a *BroadSilenceMatcherAnalyzer) ID() string      { return BroadSilenceMatcherAnalyzerID }
func (a *BroadSilenceMatcherAnalyzer) Name() string    { return "Broad Silence Matcher" }
func (a *BroadSilenceMatcherAnalyzer) Version() string { return "0.1.0" }
func (a *BroadSilenceMatcherAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeSilence}
}

type silenceMatcherDetail struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"is_regex"`
	IsEqual bool   `json:"is_equal"`
}

func (a *BroadSilenceMatcherAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	silences, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeSilence})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, silence := range silences {
		if !activeGovernedSilence(silence) {
			continue
		}
		details := silenceMatcherDetails(silence)
		reason, broad := broadSilenceMatcherReason(details)
		if !broad {
			continue
		}
		severity := model.SeverityWarning
		if len(details) == 0 {
			severity = model.SeverityCritical
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), silence.ID), Type: "BroadSilenceMatcher",
			Severity: severity, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: silence.ID, Type: silence.Type, Name: silence.Name},
			Evidence:       []string{fmt.Sprintf("%s silence %q has broad matcher scope: %s", silence.Source.System, silence.Name, reason)},
			Recommendation: "用 alertname、service、team、cluster、namespace 等稳定标签缩小静默范围，避免仅使用负向条件或全匹配正则；上线前确认影响的告警集合。",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "reason": reason, "matchers": silence.Metadata[model.MetadataSilenceMatchers]},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func silenceMatcherDetails(silence model.Resource) []silenceMatcherDetail {
	var details []silenceMatcherDetail
	if raw := strings.TrimSpace(silence.Metadata[model.MetadataSilenceMatcherDetails]); raw != "" {
		if json.Unmarshal([]byte(raw), &details) == nil {
			return details
		}
	}
	for _, raw := range strings.Split(silence.Metadata[model.MetadataSilenceMatchers], ",") {
		raw = strings.TrimSpace(raw)
		for _, operator := range []string{"!~", "=~", "!=", "="} {
			if index := strings.Index(raw, operator); index > 0 {
				details = append(details, silenceMatcherDetail{Name: strings.TrimSpace(raw[:index]), Value: strings.TrimSpace(raw[index+len(operator):]), IsRegex: strings.Contains(operator, "~"), IsEqual: !strings.HasPrefix(operator, "!")})
				break
			}
		}
	}
	return details
}

func broadSilenceMatcherReason(details []silenceMatcherDetail) (string, bool) {
	if len(details) == 0 {
		return "no valid matchers", true
	}
	negativeCount := 0
	for _, detail := range details {
		if !detail.IsEqual {
			negativeCount++
		}
		if detail.IsRegex && detail.IsEqual && wideMatcherRegex(detail.Value) {
			return fmt.Sprintf("matcher %s=~%s accepts nearly every value", detail.Name, detail.Value), true
		}
	}
	if negativeCount == len(details) {
		return "all matchers are negative and therefore select a wide complement", true
	}
	return "", false
}

func wideMatcherRegex(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "(?i)")
	value = strings.TrimPrefix(value, "^")
	value = strings.TrimSuffix(value, "$")
	return value == ".*" || value == ".+"
}
