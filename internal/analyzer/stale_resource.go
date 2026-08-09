package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const StaleResourceAnalyzerID = "builtin.stale_resource"

const defaultStaleResourceThreshold = 30 * 24 * time.Hour

type StaleResourceAnalyzer struct{}

func NewStaleResourceAnalyzer() *StaleResourceAnalyzer {
	return &StaleResourceAnalyzer{}
}

func (a *StaleResourceAnalyzer) ID() string {
	return StaleResourceAnalyzerID
}

func (a *StaleResourceAnalyzer) Name() string {
	return "Stale Resource"
}

func (a *StaleResourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *StaleResourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeMetric,
		model.ResourceTypeDashboard,
		model.ResourceTypePanel,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeDatasource,
	}
}

func (a *StaleResourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := lifecycleResourceCandidates(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	threshold := durationConfig(analysis.Config, "stale_resource_threshold", defaultStaleResourceThreshold)
	for _, resource := range resources {
		lastUsedAt, ok := parseLastUsedAt(resource)
		if !ok {
			continue
		}
		age := now.Sub(lastUsedAt)
		if age <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "StaleResource",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s %q was last used at %s, threshold is %s", resource.Type, resource.Name, lastUsedAt.Format(time.RFC3339), threshold),
			},
			Recommendation: "确认该资源是否仍有使用价值；长期未使用的资源建议归档、下线或补充保留原因。",
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

func lifecycleResourceCandidates(ctx context.Context, resources storage.ResourceRepository) ([]model.Resource, error) {
	candidates := make([]model.Resource, 0)
	for _, resourceType := range []model.ResourceType{
		model.ResourceTypeMetric,
		model.ResourceTypeDashboard,
		model.ResourceTypePanel,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeDatasource,
	} {
		items, err := resources.List(ctx, storage.ResourceFilter{Type: resourceType})
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, items...)
	}
	return candidates, nil
}

func parseLastUsedAt(resource model.Resource) (time.Time, bool) {
	raw := resource.Metadata[model.MetadataLastUsedAt]
	if raw == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
