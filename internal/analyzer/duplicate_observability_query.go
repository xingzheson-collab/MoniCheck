package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
)

const DuplicateObservabilityQueryAnalyzerID = "builtin.duplicate_observability_query"

type DuplicateObservabilityQueryAnalyzer struct{}

func NewDuplicateObservabilityQueryAnalyzer() *DuplicateObservabilityQueryAnalyzer {
	return &DuplicateObservabilityQueryAnalyzer{}
}

func (a *DuplicateObservabilityQueryAnalyzer) ID() string {
	return DuplicateObservabilityQueryAnalyzerID
}

func (a *DuplicateObservabilityQueryAnalyzer) Name() string {
	return "Duplicate Observability Query"
}

func (a *DuplicateObservabilityQueryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DuplicateObservabilityQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel}
}

func (a *DuplicateObservabilityQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listQueryResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	groups := make(map[string][]model.Resource)
	originalQuery := make(map[string]string)
	languageByKey := make(map[string]string)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		language := strings.ToLower(strings.TrimSpace(resource.Metadata[model.MetadataQueryLanguage]))
		query := strings.TrimSpace(resource.Metadata[model.MetadataQuery])
		if language == "" || language == "promql" || query == "" {
			continue
		}
		normalized := normalizeDuplicateQuery(query)
		if normalized == "" {
			continue
		}
		key := language + ":" + normalized
		groups[key] = append(groups[key], resource)
		languageByKey[key] = language
		if originalQuery[key] == "" {
			originalQuery[key] = query
		}
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for key, duplicates := range groups {
		if len(duplicates) <= 1 {
			continue
		}
		sortResourcesByTypeAndName(duplicates)
		primary := duplicates[0]
		duplicateNames := resourceNames(duplicates)
		language := languageByKey[key]
		for _, duplicate := range duplicates[1:] {
			findings = append(findings, model.Finding{
				ID:       model.StableID(a.ID(), duplicate.ID, key),
				Type:     "DuplicateObservabilityQuery",
				Severity: model.SeverityInfo,
				Resource: model.ResourceRef{
					ID:   duplicate.ID,
					Type: duplicate.Type,
					Name: duplicate.Name,
				},
				Evidence: []string{
					fmt.Sprintf("resource %q repeats a %s query used by %q", duplicate.Name, language, primary.Name),
					fmt.Sprintf("duplicate resources: %s", strings.Join(duplicateNames, ", ")),
				},
				Recommendation: "将重复的日志或链路查询沉淀为共享 Dashboard 变量、Library Panel、标准排障视图或指标化聚合，减少重复维护和重复扫描。",
				Metadata: map[string]string{
					"analyzer_id":      a.ID(),
					"duplicate_count":  fmt.Sprintf("%d", len(duplicates)),
					"primary_resource": primary.ID,
					"query_language":   language,
					"normalized_query": strings.TrimPrefix(key, language+":"),
					"query":            originalQuery[key],
				},
				Status:    model.FindingStatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}
	return findings, nil
}
