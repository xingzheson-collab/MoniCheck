package analyzer

import (
	"context"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const EmptyNotificationTemplateAnalyzerID = "builtin.empty_notification_template"

type EmptyNotificationTemplateAnalyzer struct{}

func NewEmptyNotificationTemplateAnalyzer() *EmptyNotificationTemplateAnalyzer {
	return &EmptyNotificationTemplateAnalyzer{}
}
func (a *EmptyNotificationTemplateAnalyzer) ID() string      { return EmptyNotificationTemplateAnalyzerID }
func (a *EmptyNotificationTemplateAnalyzer) Name() string    { return "Empty Notification Template" }
func (a *EmptyNotificationTemplateAnalyzer) Version() string { return "0.1.0" }
func (a *EmptyNotificationTemplateAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationTemplate}
}

func (a *EmptyNotificationTemplateAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationTemplate})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if !isActiveGrafanaNotificationTemplate(resource) || notificationPolicyMetadataInt(resource, model.MetadataTemplateDefinitionCount) > 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "EmptyNotificationTemplate", Severity: model.SeverityWarning,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{"Grafana notification template group contains no named template definition"},
			Recommendation: "为模板组增加有效的 `{{ define \"name\" }}...{{ end }}` 定义，或删除空模板组。",
			Metadata:       map[string]string{"analyzer_id": a.ID()}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func isActiveGrafanaNotificationTemplate(resource model.Resource) bool {
	return resource.Type == model.ResourceTypeNotificationTemplate && resource.Source.System == "grafana" && resource.Status == model.ResourceStatusActive && resource.Metadata[model.MetadataTemplateDeclared] == "true"
}
