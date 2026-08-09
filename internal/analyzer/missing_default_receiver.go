package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const MissingDefaultReceiverAnalyzerID = "builtin.missing_default_receiver"

type MissingDefaultReceiverAnalyzer struct{}

func NewMissingDefaultReceiverAnalyzer() *MissingDefaultReceiverAnalyzer {
	return &MissingDefaultReceiverAnalyzer{}
}

func (a *MissingDefaultReceiverAnalyzer) ID() string { return MissingDefaultReceiverAnalyzerID }

func (a *MissingDefaultReceiverAnalyzer) Name() string { return "Missing Default Receiver" }

func (a *MissingDefaultReceiverAnalyzer) Version() string { return "0.1.0" }

func (a *MissingDefaultReceiverAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}

func (a *MissingDefaultReceiverAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	policies, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, policy := range policies {
		if !isActiveNotificationPolicy(policy) || strings.TrimSpace(policy.Metadata[model.MetadataPolicyDefaultReceiver]) != "" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), policy.ID),
			Type:           "MissingDefaultReceiver",
			Severity:       model.SeverityCritical,
			Resource:       model.ResourceRef{ID: policy.ID, Type: policy.Type, Name: policy.Name},
			Evidence:       []string{fmt.Sprintf("%s notification policy has no default receiver", policy.Source.System)},
			Recommendation: "为通知策略根路由配置有效的默认 receiver/contact point，确保未命中子路由的告警仍有兜底通知目标。",
			Metadata:       map[string]string{"analyzer_id": a.ID()},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func isActiveNotificationPolicy(policy model.Resource) bool {
	return policy.Type == model.ResourceTypeNotificationPolicy &&
		policy.Status == model.ResourceStatusActive &&
		(policy.Source.System == "alertmanager" || policy.Source.System == "grafana")
}
