package analyzer

import (
	"context"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UndefinedNotificationTemplateAnalyzerID = "builtin.undefined_notification_template"

type UndefinedNotificationTemplateAnalyzer struct{}

func NewUndefinedNotificationTemplateAnalyzer() *UndefinedNotificationTemplateAnalyzer {
	return &UndefinedNotificationTemplateAnalyzer{}
}
func (a *UndefinedNotificationTemplateAnalyzer) ID() string {
	return UndefinedNotificationTemplateAnalyzerID
}
func (a *UndefinedNotificationTemplateAnalyzer) Name() string {
	return "Undefined Notification Template"
}
func (a *UndefinedNotificationTemplateAnalyzer) Version() string { return "0.1.0" }
func (a *UndefinedNotificationTemplateAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationTemplate}
}

func (a *UndefinedNotificationTemplateAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationTemplate})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive || resource.Source.System != "grafana" || resource.Metadata[model.MetadataTemplateDeclared] != "false" || notificationPolicyMetadataInt(resource, model.MetadataTemplateReferenceCount) == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "UndefinedNotificationTemplate", Severity: model.SeverityCritical,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{"Grafana contact point references a custom notification template that was not found in discovered template groups"},
			Recommendation: "在 Grafana 中声明该 notification template，或修正 contact point 中的模板名称引用。",
			Metadata:       map[string]string{"analyzer_id": a.ID()}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
