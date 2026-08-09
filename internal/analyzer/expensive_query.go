package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const ExpensiveQueryAnalyzerID = "builtin.expensive_query"

const defaultExpensiveQueryLengthThreshold = 300

type ExpensiveQueryAnalyzer struct{}

func NewExpensiveQueryAnalyzer() *ExpensiveQueryAnalyzer {
	return &ExpensiveQueryAnalyzer{}
}

func (a *ExpensiveQueryAnalyzer) ID() string {
	return ExpensiveQueryAnalyzerID
}

func (a *ExpensiveQueryAnalyzer) Name() string {
	return "Expensive Query"
}

func (a *ExpensiveQueryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *ExpensiveQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *ExpensiveQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listQueryResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	threshold := intConfig(analysis.Config, "expensive_query_length_threshold", defaultExpensiveQueryLengthThreshold)
	for _, resource := range resources {
		query := strings.TrimSpace(resource.Metadata[model.MetadataPromQL])
		if len(query) <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "ExpensiveQuery",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("PromQL length is %d, threshold is %d", len(query), threshold),
			},
			Recommendation: "检查该 PromQL 是否可以通过 Recording Rule、标签过滤或聚合层级优化。",
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

func listQueryResources(ctx context.Context, resources storage.ResourceRepository) ([]model.Resource, error) {
	queryResources := make([]model.Resource, 0)
	for _, resourceType := range []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule} {
		items, err := resources.List(ctx, storage.ResourceFilter{Type: resourceType})
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if !isActiveQueryResource(item) {
				continue
			}
			queryResources = append(queryResources, item)
		}
	}
	return queryResources, nil
}

func isActiveQueryResource(resource model.Resource) bool {
	if resource.Status != model.ResourceStatusActive {
		return false
	}
	if resource.Type == model.ResourceTypeAlertRule && isDisabledAlert(resource) {
		return false
	}
	return true
}
