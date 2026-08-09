package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const DisabledAlertAnalyzerID = "builtin.disabled_alert"

type DisabledAlertAnalyzer struct{}

func NewDisabledAlertAnalyzer() *DisabledAlertAnalyzer {
	return &DisabledAlertAnalyzer{}
}

func (a *DisabledAlertAnalyzer) ID() string {
	return DisabledAlertAnalyzerID
}

func (a *DisabledAlertAnalyzer) Name() string {
	return "Disabled Alert"
}

func (a *DisabledAlertAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DisabledAlertAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *DisabledAlertAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alertRules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, alertRule := range alertRules {
		if !isDisabledAlert(alertRule) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alertRule.ID),
			Type:     "DisabledAlert",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alertRule.ID,
				Type: alertRule.Type,
				Name: alertRule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alert rule %q is marked as disabled", alertRule.Name),
			},
			Recommendation: "确认该禁用告警是否仍需要保留；长期禁用的规则建议删除、归档或补充禁用原因。",
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

func isDisabledAlert(alertRule model.Resource) bool {
	if alertRule.Status == model.ResourceStatusDeprecated {
		return true
	}
	enabled := strings.TrimSpace(strings.ToLower(alertRule.Metadata[model.MetadataEnabled]))
	if enabled == "false" || enabled == "0" || enabled == "no" {
		return true
	}
	disabled := strings.TrimSpace(strings.ToLower(alertRule.Metadata[model.MetadataDisabled]))
	return disabled == "true" || disabled == "1" || disabled == "yes"
}
