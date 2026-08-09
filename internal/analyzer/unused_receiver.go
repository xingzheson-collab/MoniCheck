package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UnusedReceiverAnalyzerID = "builtin.unused_receiver"

type UnusedReceiverAnalyzer struct{}

func NewUnusedReceiverAnalyzer() *UnusedReceiverAnalyzer {
	return &UnusedReceiverAnalyzer{}
}

func (a *UnusedReceiverAnalyzer) ID() string {
	return UnusedReceiverAnalyzerID
}

func (a *UnusedReceiverAnalyzer) Name() string {
	return "Unused Receiver"
}

func (a *UnusedReceiverAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnusedReceiverAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeReceiver}
}

func (a *UnusedReceiverAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	receivers, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeReceiver})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, receiver := range receivers {
		if !isActiveNotificationReceiver(receiver) {
			continue
		}
		if receiver.Metadata["declared"] != "true" {
			continue
		}
		if receiver.Metadata["referenced_by_route"] == "true" || receiver.Metadata["seen_in_alerts"] == "true" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), receiver.ID),
			Type:     "UnusedReceiver",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   receiver.ID,
				Type: receiver.Type,
				Name: receiver.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s receiver %q is declared but not referenced by any route or runtime alert", receiver.Source.System, receiver.Name),
			},
			Recommendation: "确认该 receiver 是否仍需要保留；未被 route 引用且运行时未出现的 receiver 建议删除或归档，减少通知配置漂移。",
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
