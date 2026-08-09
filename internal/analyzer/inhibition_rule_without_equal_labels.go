package analyzer

import (
	"context"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const InhibitionRuleWithoutEqualLabelsAnalyzerID = "builtin.inhibition_rule_without_equal_labels"

type InhibitionRuleWithoutEqualLabelsAnalyzer struct{}

func NewInhibitionRuleWithoutEqualLabelsAnalyzer() *InhibitionRuleWithoutEqualLabelsAnalyzer {
	return &InhibitionRuleWithoutEqualLabelsAnalyzer{}
}
func (a *InhibitionRuleWithoutEqualLabelsAnalyzer) ID() string {
	return InhibitionRuleWithoutEqualLabelsAnalyzerID
}
func (a *InhibitionRuleWithoutEqualLabelsAnalyzer) Name() string {
	return "Inhibition Rule Without Equal Labels"
}
func (a *InhibitionRuleWithoutEqualLabelsAnalyzer) Version() string { return "0.1.0" }
func (a *InhibitionRuleWithoutEqualLabelsAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInhibitionRule}
}

func (a *InhibitionRuleWithoutEqualLabelsAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInhibitionRule})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, rule := range rules {
		if !isActiveInhibitionRule(rule) || notificationPolicyMetadataInt(rule, model.MetadataInhibitionEqualLabelCount) > 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), rule.ID), Type: "InhibitionRuleWithoutEqualLabels", Severity: model.SeverityWarning,
			Resource:       model.ResourceRef{ID: rule.ID, Type: rule.Type, Name: rule.Name},
			Evidence:       []string{"inhibition rule has no equal labels constraining source and target alerts"},
			Recommendation: "为 inhibition rule 增加 service、cluster、namespace、instance 或 alertname 等 equal 标签，避免一个故障域的 source alert 抑制其他故障域的 target alerts。",
			Metadata:       map[string]string{"analyzer_id": a.ID()},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
