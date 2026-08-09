package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const InvalidAlertDurationAnalyzerID = "builtin.invalid_alert_duration"

type InvalidAlertDurationAnalyzer struct{}

func NewInvalidAlertDurationAnalyzer() *InvalidAlertDurationAnalyzer {
	return &InvalidAlertDurationAnalyzer{}
}

func (a *InvalidAlertDurationAnalyzer) ID() string {
	return InvalidAlertDurationAnalyzerID
}

func (a *InvalidAlertDurationAnalyzer) Name() string {
	return "Invalid Alert Duration"
}

func (a *InvalidAlertDurationAnalyzer) Version() string {
	return "0.1.0"
}

func (a *InvalidAlertDurationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *InvalidAlertDurationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		durationKey, durationValue, ok := alertDurationValue(alertRule.Metadata)
		if !ok {
			continue
		}
		parsed, ok := parseAlertDuration(durationValue)
		if ok && parsed > 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alertRule.ID, durationValue),
			Type:     "InvalidAlertDuration",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alertRule.ID,
				Type: alertRule.Type,
				Name: alertRule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alert rule %q has invalid alert duration %q in %s", alertRule.Name, durationValue, durationKey),
			},
			Recommendation: "将告警持续时间调整为可解析的正数 duration，例如 5m、10m 或数字秒数，避免规则管理平台和治理分析对告警抑制窗口产生分歧。",
			Metadata: map[string]string{
				"analyzer_id":  a.ID(),
				"duration_key": durationKey,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func parseAlertDuration(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	parsed, err := time.ParseDuration(raw)
	if err == nil {
		return parsed, true
	}
	seconds, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}
