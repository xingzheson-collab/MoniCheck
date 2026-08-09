package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
)

const OldResourceAnalyzerID = "builtin.old_resource"

const defaultOldResourceAgeThreshold = 180 * 24 * time.Hour

type OldResourceAnalyzer struct{}

func NewOldResourceAnalyzer() *OldResourceAnalyzer {
	return &OldResourceAnalyzer{}
}

func (a *OldResourceAnalyzer) ID() string {
	return OldResourceAnalyzerID
}

func (a *OldResourceAnalyzer) Name() string {
	return "Old Resource"
}

func (a *OldResourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *OldResourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeMetric,
		model.ResourceTypeDashboard,
		model.ResourceTypePanel,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeDatasource,
	}
}

func (a *OldResourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := lifecycleResourceCandidates(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	threshold := durationConfig(analysis.Config, "old_resource_age_threshold", defaultOldResourceAgeThreshold)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive || resource.CreatedAt.IsZero() {
			continue
		}
		age := now.Sub(resource.CreatedAt)
		if age <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "OldResource",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s %q was created at %s, age is %s and threshold is %s", resource.Type, resource.Name, resource.CreatedAt.Format(time.RFC3339), age.Round(time.Hour), threshold),
			},
			Recommendation: "复审长期存在的监控资源，确认 owner、用途、依赖关系和保留理由仍然有效；不再需要的资源建议归档或下线。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"created_at":  resource.CreatedAt.Format(time.RFC3339),
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
