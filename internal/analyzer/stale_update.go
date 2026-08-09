package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
)

const StaleUpdateAnalyzerID = "builtin.stale_update"

const defaultStaleUpdateThreshold = 90 * 24 * time.Hour

type StaleUpdateAnalyzer struct{}

func NewStaleUpdateAnalyzer() *StaleUpdateAnalyzer {
	return &StaleUpdateAnalyzer{}
}

func (a *StaleUpdateAnalyzer) ID() string {
	return StaleUpdateAnalyzerID
}

func (a *StaleUpdateAnalyzer) Name() string {
	return "Stale Update"
}

func (a *StaleUpdateAnalyzer) Version() string {
	return "0.1.0"
}

func (a *StaleUpdateAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeDashboard,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeDatasource,
	}
}

func (a *StaleUpdateAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := lifecycleResourceCandidates(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	threshold := durationConfig(analysis.Config, "stale_update_threshold", defaultStaleUpdateThreshold)
	for _, resource := range resources {
		if !isStaleUpdateResource(resource.Type) || resource.Status != model.ResourceStatusActive {
			continue
		}
		updatedAt, ok := resourceUpdatedAt(resource)
		if !ok {
			continue
		}
		age := now.Sub(updatedAt)
		if age <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "StaleUpdate",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s %q was last updated at %s, age is %s and threshold is %s", resource.Type, resource.Name, updatedAt.Format(time.RFC3339), age.Round(time.Hour), threshold),
			},
			Recommendation: "复审长期未更新的监控配置，确认查询、阈值、owner 和依赖关系仍符合当前系统状态。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"updated_at":  updatedAt.Format(time.RFC3339),
				"age":         age.Round(time.Hour).String(),
				"threshold":   threshold.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func isStaleUpdateResource(resourceType model.ResourceType) bool {
	switch resourceType {
	case model.ResourceTypeDashboard, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule, model.ResourceTypeDatasource:
		return true
	default:
		return false
	}
}

func resourceUpdatedAt(resource model.Resource) (time.Time, bool) {
	if parsed, ok := parseRFC3339Metadata(resource.Metadata[model.MetadataUpdatedAt]); ok {
		return parsed, true
	}
	if !resource.UpdatedAt.IsZero() {
		return resource.UpdatedAt, true
	}
	return time.Time{}, false
}

func parseRFC3339Metadata(raw string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}
