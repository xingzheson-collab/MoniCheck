package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UndefinedReceiverAnalyzerID = "builtin.undefined_receiver"

type UndefinedReceiverAnalyzer struct{}

func NewUndefinedReceiverAnalyzer() *UndefinedReceiverAnalyzer {
	return &UndefinedReceiverAnalyzer{}
}

func (a *UndefinedReceiverAnalyzer) ID() string {
	return UndefinedReceiverAnalyzerID
}

func (a *UndefinedReceiverAnalyzer) Name() string {
	return "Undefined Receiver"
}

func (a *UndefinedReceiverAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UndefinedReceiverAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeReceiver}
}

func (a *UndefinedReceiverAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if receiver.Metadata["referenced_by_route"] != "true" || receiver.Metadata["declared"] != "false" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), receiver.ID),
			Type:     "UndefinedReceiver",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   receiver.ID,
				Type: receiver.Type,
				Name: receiver.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s route references receiver %q but it is not declared", receiver.Source.System, receiver.Name),
			},
			Recommendation: "补充该 receiver，或修正通知策略指向已有 receiver；未定义 receiver 会导致对应路由无法正常发送通知。",
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
