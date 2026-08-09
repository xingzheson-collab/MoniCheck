package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const AlertNamingAnalyzerID = "builtin.alert_naming"

var alertNamePattern = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)

type AlertNamingAnalyzer struct{}

func NewAlertNamingAnalyzer() *AlertNamingAnalyzer {
	return &AlertNamingAnalyzer{}
}

func (a *AlertNamingAnalyzer) ID() string {
	return AlertNamingAnalyzerID
}

func (a *AlertNamingAnalyzer) Name() string {
	return "Alert Naming Convention"
}

func (a *AlertNamingAnalyzer) Version() string {
	return "0.1.0"
}

func (a *AlertNamingAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *AlertNamingAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alertRules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, alertRule := range alertRules {
		if !isActiveQueryResource(alertRule) {
			continue
		}
		if alertNamePattern.MatchString(alertRule.Name) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alertRule.ID),
			Type:     "AlertNamingViolation",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alertRule.ID,
				Type: alertRule.Type,
				Name: alertRule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alert rule %q does not follow PascalCase naming convention", alertRule.Name),
			},
			Recommendation: "将告警规则命名为清晰的 PascalCase，例如 APIHighErrorRate 或 NodeDiskAlmostFull。",
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
