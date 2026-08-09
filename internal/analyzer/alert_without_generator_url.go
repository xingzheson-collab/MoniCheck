package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const AlertWithoutGeneratorURLAnalyzerID = "builtin.alert_without_generator_url"

type AlertWithoutGeneratorURLAnalyzer struct{}

func NewAlertWithoutGeneratorURLAnalyzer() *AlertWithoutGeneratorURLAnalyzer {
	return &AlertWithoutGeneratorURLAnalyzer{}
}

func (a *AlertWithoutGeneratorURLAnalyzer) ID() string {
	return AlertWithoutGeneratorURLAnalyzerID
}

func (a *AlertWithoutGeneratorURLAnalyzer) Name() string {
	return "Alert Without Generator URL"
}

func (a *AlertWithoutGeneratorURLAnalyzer) Version() string {
	return "0.1.0"
}

func (a *AlertWithoutGeneratorURLAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlert}
}

func (a *AlertWithoutGeneratorURLAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alerts, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlert})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, alert := range alerts {
		if alert.Source.System != "alertmanager" {
			continue
		}
		if alert.Status != model.ResourceStatusActive {
			continue
		}
		if !isActiveAlertState(alert.Metadata[model.MetadataAlertState]) {
			continue
		}
		if strings.TrimSpace(alert.Metadata[model.MetadataGeneratorURL]) != "" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alert.ID),
			Type:     "AlertWithoutGeneratorURL",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alert.ID,
				Type: alert.Type,
				Name: alert.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alertmanager alert %q has no generator URL", alert.Name),
			},
			Recommendation: "确保告警携带 generator URL，便于值班人员从通知回跳到 Prometheus 表达式、图表和原始告警上下文。",
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

func isActiveAlertState(state string) bool {
	state = strings.TrimSpace(state)
	return state == "" || strings.EqualFold(state, "active") || strings.EqualFold(state, "firing")
}

func isActiveRuntimeAlert(resource model.Resource) bool {
	return resource.Status == model.ResourceStatusActive && isActiveAlertState(resource.Metadata[model.MetadataAlertState])
}
