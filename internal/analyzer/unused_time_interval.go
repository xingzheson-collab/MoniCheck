package analyzer

import (
	"context"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UnusedTimeIntervalAnalyzerID = "builtin.unused_time_interval"

type UnusedTimeIntervalAnalyzer struct{}

func NewUnusedTimeIntervalAnalyzer() *UnusedTimeIntervalAnalyzer {
	return &UnusedTimeIntervalAnalyzer{}
}
func (a *UnusedTimeIntervalAnalyzer) ID() string      { return UnusedTimeIntervalAnalyzerID }
func (a *UnusedTimeIntervalAnalyzer) Name() string    { return "Unused Notification Time Interval" }
func (a *UnusedTimeIntervalAnalyzer) Version() string { return "0.1.0" }
func (a *UnusedTimeIntervalAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTimeInterval}
}

func (a *UnusedTimeIntervalAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTimeInterval})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		refs := notificationPolicyMetadataInt(resource, model.MetadataTimeIntervalMuteRefCount) + notificationPolicyMetadataInt(resource, model.MetadataTimeIntervalActiveRefCount)
		if resource.Status != model.ResourceStatusActive || !isNotificationTimeIntervalSystem(resource.Source.System) || resource.Metadata[model.MetadataTimeIntervalDeclared] != "true" || refs != 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "UnusedTimeInterval", Severity: model.SeverityWarning,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{"declared Alertmanager time interval is not referenced by any notification route"},
			Recommendation: "删除未使用的时间窗口，或将其明确应用到需要静默/限定生效时间的 route，减少配置漂移。",
			Metadata:       map[string]string{"analyzer_id": a.ID()}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
