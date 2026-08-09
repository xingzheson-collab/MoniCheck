package analyzer

import (
	"context"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UndefinedTimeIntervalAnalyzerID = "builtin.undefined_time_interval"

type UndefinedTimeIntervalAnalyzer struct{}

func NewUndefinedTimeIntervalAnalyzer() *UndefinedTimeIntervalAnalyzer {
	return &UndefinedTimeIntervalAnalyzer{}
}
func (a *UndefinedTimeIntervalAnalyzer) ID() string      { return UndefinedTimeIntervalAnalyzerID }
func (a *UndefinedTimeIntervalAnalyzer) Name() string    { return "Undefined Notification Time Interval" }
func (a *UndefinedTimeIntervalAnalyzer) Version() string { return "0.1.0" }
func (a *UndefinedTimeIntervalAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTimeInterval}
}

func (a *UndefinedTimeIntervalAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTimeInterval})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		refs := notificationPolicyMetadataInt(resource, model.MetadataTimeIntervalMuteRefCount) + notificationPolicyMetadataInt(resource, model.MetadataTimeIntervalActiveRefCount)
		if resource.Status != model.ResourceStatusActive || !isNotificationTimeIntervalSystem(resource.Source.System) || resource.Metadata[model.MetadataTimeIntervalDeclared] != "false" || refs == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "UndefinedTimeInterval", Severity: model.SeverityCritical,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{"notification route references a time interval that is not declared in the source alerting configuration"},
			Recommendation: "在告警平台中声明该时间窗口，或修正 notification route 的 mute_time_intervals/active_time_intervals 引用。",
			Metadata:       map[string]string{"analyzer_id": a.ID()}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func isNotificationTimeIntervalSystem(system string) bool {
	return system == "alertmanager" || system == "grafana"
}
