package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const AlertWithoutReceiverAnalyzerID = "builtin.alert_without_receiver"

type AlertWithoutReceiverAnalyzer struct{}

func NewAlertWithoutReceiverAnalyzer() *AlertWithoutReceiverAnalyzer {
	return &AlertWithoutReceiverAnalyzer{}
}

func (a *AlertWithoutReceiverAnalyzer) ID() string {
	return AlertWithoutReceiverAnalyzerID
}

func (a *AlertWithoutReceiverAnalyzer) Name() string {
	return "Alert Without Receiver"
}

func (a *AlertWithoutReceiverAnalyzer) Version() string {
	return "0.1.0"
}

func (a *AlertWithoutReceiverAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlert}
}

func (a *AlertWithoutReceiverAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if strings.TrimSpace(alert.Metadata[model.MetadataReceiverNames]) != "" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alert.ID),
			Type:     "AlertWithoutReceiver",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   alert.ID,
				Type: alert.Type,
				Name: alert.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alertmanager alert %q has no receiver names", alert.Name),
			},
			Recommendation: "检查 Alertmanager route 配置，确保 firing 告警会路由到至少一个有效 receiver，避免告警无人接收。",
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
