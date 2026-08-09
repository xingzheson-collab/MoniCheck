package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const ReceiverWithoutIntegrationAnalyzerID = "builtin.receiver_without_integration"

type ReceiverWithoutIntegrationAnalyzer struct{}

func NewReceiverWithoutIntegrationAnalyzer() *ReceiverWithoutIntegrationAnalyzer {
	return &ReceiverWithoutIntegrationAnalyzer{}
}

func (a *ReceiverWithoutIntegrationAnalyzer) ID() string {
	return ReceiverWithoutIntegrationAnalyzerID
}

func (a *ReceiverWithoutIntegrationAnalyzer) Name() string {
	return "Receiver Without Integration"
}

func (a *ReceiverWithoutIntegrationAnalyzer) Version() string {
	return "0.1.0"
}

func (a *ReceiverWithoutIntegrationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeReceiver}
}

func (a *ReceiverWithoutIntegrationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	receivers, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeReceiver})
	if err != nil {
		return nil, err
	}

	blackholeReceivers := receiverNameSet(stringSliceConfig(analysis.Config, "blackhole_receiver_names", defaultBlackholeReceiverNames))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, receiver := range receivers {
		if !isActiveNotificationReceiver(receiver) {
			continue
		}
		if receiver.Metadata["declared"] != "true" {
			continue
		}
		receiverName := strings.TrimSpace(receiver.Metadata["receiver_name"])
		if receiverName == "" {
			receiverName = receiver.Name
		}
		if blackholeReceivers[strings.ToLower(receiverName)] {
			continue
		}
		if strings.TrimSpace(receiver.Metadata[model.MetadataReceiverIntegrations]) != "" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), receiver.ID),
			Type:     "ReceiverWithoutIntegration",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   receiver.ID,
				Type: receiver.Type,
				Name: receiver.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s receiver %q is declared without any notification integration config", receiver.Source.System, receiver.Name),
			},
			Recommendation: "为该 receiver 配置至少一种通知集成；如果它是有意丢弃告警的 receiver，请使用明确的 blackhole 命名并纳入黑洞接收器治理。",
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

func isActiveNotificationReceiver(receiver model.Resource) bool {
	return receiver.Type == model.ResourceTypeReceiver &&
		(receiver.Source.System == "alertmanager" || receiver.Source.System == "grafana") &&
		receiver.Status == model.ResourceStatusActive
}
