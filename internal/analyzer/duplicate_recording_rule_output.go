package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const DuplicateRecordingRuleOutputAnalyzerID = "builtin.duplicate_recording_rule_output"

type DuplicateRecordingRuleOutputAnalyzer struct{}

func NewDuplicateRecordingRuleOutputAnalyzer() *DuplicateRecordingRuleOutputAnalyzer {
	return &DuplicateRecordingRuleOutputAnalyzer{}
}

func (a *DuplicateRecordingRuleOutputAnalyzer) ID() string {
	return DuplicateRecordingRuleOutputAnalyzerID
}

func (a *DuplicateRecordingRuleOutputAnalyzer) Name() string {
	return "Duplicate Recording Rule Output"
}

func (a *DuplicateRecordingRuleOutputAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DuplicateRecordingRuleOutputAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeRecordingRule}
}

func (a *DuplicateRecordingRuleOutputAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	recordingRules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeRecordingRule})
	if err != nil {
		return nil, err
	}

	groups := make(map[string][]model.Resource)
	for _, rule := range recordingRules {
		if rule.Status != model.ResourceStatusActive {
			continue
		}
		output := recordingRuleOutput(rule)
		if output == "" {
			continue
		}
		groups[output] = append(groups[output], rule)
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for output, duplicates := range groups {
		if len(duplicates) < 2 {
			continue
		}
		sort.Slice(duplicates, func(i, j int) bool {
			return duplicates[i].ID < duplicates[j].ID
		})
		original := duplicates[0]
		for _, duplicate := range duplicates[1:] {
			findings = append(findings, model.Finding{
				ID:       model.StableID(a.ID(), output, duplicate.ID),
				Type:     "DuplicateRecordingRuleOutput",
				Severity: model.SeverityWarning,
				Resource: model.ResourceRef{
					ID:   duplicate.ID,
					Type: duplicate.Type,
					Name: duplicate.Name,
				},
				Evidence: []string{
					fmt.Sprintf("recording rule %q produces the same output metric %q as %q", duplicate.Name, output, original.Name),
				},
				Recommendation: "确认同名 Recording Rule 输出是否来自重复规则文件或冲突分组；同名输出会让下游查询语义不稳定，建议合并或重命名。",
				Metadata: map[string]string{
					"analyzer_id":       a.ID(),
					"output_metric":     output,
					"duplicate_of_id":   original.ID,
					"duplicate_of_name": original.Name,
				},
				Status:    model.FindingStatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}
	return findings, nil
}

func recordingRuleOutput(rule model.Resource) string {
	output := strings.TrimSpace(rule.Metadata[model.MetadataRecordingRuleOutput])
	if output != "" {
		return output
	}
	return strings.TrimSpace(rule.Name)
}
