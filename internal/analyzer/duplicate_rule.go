package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
)

const DuplicateRuleAnalyzerID = "builtin.duplicate_rule"

type DuplicateRuleAnalyzer struct{}

func NewDuplicateRuleAnalyzer() *DuplicateRuleAnalyzer {
	return &DuplicateRuleAnalyzer{}
}

func (a *DuplicateRuleAnalyzer) ID() string {
	return DuplicateRuleAnalyzerID
}

func (a *DuplicateRuleAnalyzer) Name() string {
	return "Duplicate Rule"
}

func (a *DuplicateRuleAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DuplicateRuleAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *DuplicateRuleAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := listRules(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	groups := make(map[string][]model.Resource)
	for _, rule := range rules {
		if !isActiveQueryResource(rule) {
			continue
		}
		query := normalizeRuleQuery(rule.Metadata[model.MetadataPromQL])
		if query == "" {
			continue
		}
		groups[query] = append(groups[query], rule)
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for query, duplicates := range groups {
		if len(duplicates) < 2 {
			continue
		}
		sort.Slice(duplicates, func(i, j int) bool {
			return duplicates[i].ID < duplicates[j].ID
		})

		original := duplicates[0]
		for _, duplicate := range duplicates[1:] {
			findings = append(findings, model.Finding{
				ID:       model.StableID(a.ID(), query, duplicate.ID),
				Type:     "DuplicateRule",
				Severity: model.SeverityWarning,
				Resource: model.ResourceRef{
					ID:   duplicate.ID,
					Type: duplicate.Type,
					Name: duplicate.Name,
				},
				Evidence: []string{
					fmt.Sprintf("rule %q has the same PromQL as %q", duplicate.Name, original.Name),
				},
				Recommendation: "确认重复规则是否都需要保留；如果语义相同，建议合并或删除冗余规则以降低执行成本和维护成本。",
				Metadata: map[string]string{
					"analyzer_id":        a.ID(),
					"duplicate_of_id":    original.ID,
					"duplicate_of_name":  original.Name,
					"normalized_promql":  query,
					"duplicate_group_id": model.StableID(a.ID(), query),
				},
				Status:    model.FindingStatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}
	return findings, nil
}

func normalizeRuleQuery(query string) string {
	return strings.Join(strings.Fields(query), " ")
}
