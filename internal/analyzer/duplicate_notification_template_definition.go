package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const DuplicateNotificationTemplateDefinitionAnalyzerID = "builtin.duplicate_notification_template_definition"

type DuplicateNotificationTemplateDefinitionAnalyzer struct{}

func NewDuplicateNotificationTemplateDefinitionAnalyzer() *DuplicateNotificationTemplateDefinitionAnalyzer {
	return &DuplicateNotificationTemplateDefinitionAnalyzer{}
}
func (a *DuplicateNotificationTemplateDefinitionAnalyzer) ID() string {
	return DuplicateNotificationTemplateDefinitionAnalyzerID
}
func (a *DuplicateNotificationTemplateDefinitionAnalyzer) Name() string {
	return "Duplicate Notification Template Definition"
}
func (a *DuplicateNotificationTemplateDefinitionAnalyzer) Version() string { return "0.1.0" }
func (a *DuplicateNotificationTemplateDefinitionAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationTemplate}
}

func (a *DuplicateNotificationTemplateDefinitionAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationTemplate})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		count := notificationPolicyMetadataInt(resource, model.MetadataTemplateConflictCount)
		if !isActiveGrafanaNotificationTemplate(resource) || count == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "DuplicateNotificationTemplateDefinition", Severity: model.SeverityCritical,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("Grafana notification template group contains %d definition name conflict(s): %s", count, resource.Metadata[model.MetadataTemplateConflictNames])},
			Recommendation: "为冲突的模板定义使用全局唯一名称，并避免覆盖 Grafana 或 Alertmanager 内置模板。",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "conflict_count": fmt.Sprintf("%d", count)}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
