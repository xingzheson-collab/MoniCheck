package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const MissingAlertDurationAnalyzerID = "builtin.missing_alert_duration"

type MissingAlertDurationAnalyzer struct{}

func NewMissingAlertDurationAnalyzer() *MissingAlertDurationAnalyzer {
	return &MissingAlertDurationAnalyzer{}
}

func (a *MissingAlertDurationAnalyzer) ID() string {
	return MissingAlertDurationAnalyzerID
}

func (a *MissingAlertDurationAnalyzer) Name() string {
	return "Missing Alert Duration"
}

func (a *MissingAlertDurationAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MissingAlertDurationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *MissingAlertDurationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alertRules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, alertRule := range alertRules {
		if alertRule.Status != model.ResourceStatusActive || isDisabledAlert(alertRule) {
			continue
		}
		if severity, ok := severityValue(alertRule); ok && strings.EqualFold(strings.TrimSpace(severity), "info") {
			continue
		}
		if hasAlertDuration(alertRule.Metadata) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alertRule.ID),
			Type:     "MissingAlertDuration",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alertRule.ID,
				Type: alertRule.Type,
				Name: alertRule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alert rule %q has no for/hold duration", alertRule.Name),
			},
			Recommendation: "为 warning 或 critical 告警补充 for/hold duration，例如 5m 或 10m，避免瞬时抖动直接触发通知。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func hasAlertDuration(metadata map[string]string) bool {
	_, value, ok := alertDurationValue(metadata)
	if !ok {
		return false
	}
	value = strings.TrimSpace(strings.ToLower(value))
	return value != "" && value != "0" && value != "0s" && value != "0m"
}

func alertDurationValue(metadata map[string]string) (string, string, bool) {
	for _, key := range alertDurationMetadataKeys() {
		value := strings.TrimSpace(metadata[key])
		if value != "" {
			return key, value, true
		}
	}
	return "", "", false
}

func alertDurationMetadataKeys() []string {
	return []string{
		model.MetadataAlertFor,
		"duration",
		"hold_duration",
		"holdDuration",
	}
}
