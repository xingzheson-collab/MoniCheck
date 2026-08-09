package analyzer

import (
	"context"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UnusedNotificationTemplateAnalyzerID = "builtin.unused_notification_template"

type UnusedNotificationTemplateAnalyzer struct{}

func NewUnusedNotificationTemplateAnalyzer() *UnusedNotificationTemplateAnalyzer {
	return &UnusedNotificationTemplateAnalyzer{}
}
func (a *UnusedNotificationTemplateAnalyzer) ID() string      { return UnusedNotificationTemplateAnalyzerID }
func (a *UnusedNotificationTemplateAnalyzer) Name() string    { return "Unused Notification Template" }
func (a *UnusedNotificationTemplateAnalyzer) Version() string { return "0.1.0" }
func (a *UnusedNotificationTemplateAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationTemplate}
}

func (a *UnusedNotificationTemplateAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationTemplate})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if !isActiveGrafanaNotificationTemplate(resource) || notificationPolicyMetadataInt(resource, model.MetadataTemplateDefinitionCount) == 0 || notificationPolicyMetadataInt(resource, model.MetadataTemplateReferenceCount) > 0 || strings.EqualFold(strings.TrimSpace(resource.Metadata[model.MetadataTemplateKind]), "grafana") {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "UnusedNotificationTemplate", Severity: model.SeverityWarning,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{"custom Grafana notification template group is not referenced by any discovered contact point integration"},
			Recommendation: "确认模板是否仍由外部配置使用；没有消费者的自定义模板组建议删除，或在 contact point 消息配置中明确引用。",
			Metadata:       map[string]string{"analyzer_id": a.ID()}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
