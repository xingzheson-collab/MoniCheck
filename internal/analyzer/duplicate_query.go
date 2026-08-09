package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"monicheck/internal/model"
)

const DuplicateQueryAnalyzerID = "builtin.duplicate_query"

type DuplicateQueryAnalyzer struct{}

func NewDuplicateQueryAnalyzer() *DuplicateQueryAnalyzer {
	return &DuplicateQueryAnalyzer{}
}

func (a *DuplicateQueryAnalyzer) ID() string {
	return DuplicateQueryAnalyzerID
}

func (a *DuplicateQueryAnalyzer) Name() string {
	return "Duplicate Query"
}

func (a *DuplicateQueryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DuplicateQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *DuplicateQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listQueryResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	groups := make(map[string][]model.Resource)
	originalQuery := make(map[string]string)
	for _, resource := range resources {
		query := strings.TrimSpace(resource.Metadata[model.MetadataPromQL])
		if query == "" {
			continue
		}
		normalized := normalizeDuplicateQuery(query)
		if normalized == "" {
			continue
		}
		groups[normalized] = append(groups[normalized], resource)
		if originalQuery[normalized] == "" {
			originalQuery[normalized] = query
		}
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for normalized, duplicates := range groups {
		if len(duplicates) <= 1 {
			continue
		}
		sortResourcesByTypeAndName(duplicates)
		primary := duplicates[0]
		duplicateNames := resourceNames(duplicates)
		for _, duplicate := range duplicates[1:] {
			findings = append(findings, model.Finding{
				ID:       model.StableID(a.ID(), duplicate.ID, normalized),
				Type:     "DuplicateQuery",
				Severity: model.SeverityInfo,
				Resource: model.ResourceRef{
					ID:   duplicate.ID,
					Type: duplicate.Type,
					Name: duplicate.Name,
				},
				Evidence: []string{
					fmt.Sprintf("resource %q repeats a PromQL query used by %q", duplicate.Name, primary.Name),
					fmt.Sprintf("duplicate resources: %s", strings.Join(duplicateNames, ", ")),
				},
				Recommendation: "将重复 PromQL 抽成 Recording Rule、共享 Dashboard 变量或统一查询片段，减少重复扫描和维护成本。",
				Metadata: map[string]string{
					"analyzer_id":       a.ID(),
					"duplicate_count":   fmt.Sprintf("%d", len(duplicates)),
					"primary_resource":  primary.ID,
					"normalized_promql": normalized,
					"promql":            originalQuery[normalized],
				},
				Status:    model.FindingStatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}
	return findings, nil
}

func normalizeDuplicateQuery(query string) string {
	return strings.Map(func(value rune) rune {
		if unicode.IsSpace(value) {
			return -1
		}
		return value
	}, query)
}
