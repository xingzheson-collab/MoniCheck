package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const BroadInhibitionRuleAnalyzerID = "builtin.broad_inhibition_rule"

type BroadInhibitionRuleAnalyzer struct{}

func NewBroadInhibitionRuleAnalyzer() *BroadInhibitionRuleAnalyzer {
	return &BroadInhibitionRuleAnalyzer{}
}
func (a *BroadInhibitionRuleAnalyzer) ID() string      { return BroadInhibitionRuleAnalyzerID }
func (a *BroadInhibitionRuleAnalyzer) Name() string    { return "Broad Inhibition Rule" }
func (a *BroadInhibitionRuleAnalyzer) Version() string { return "0.1.0" }
func (a *BroadInhibitionRuleAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInhibitionRule}
}

func (a *BroadInhibitionRuleAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInhibitionRule})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, rule := range rules {
		if !isActiveInhibitionRule(rule) {
			continue
		}
		sourceCount := notificationPolicyMetadataInt(rule, model.MetadataInhibitionSourceMatcherCount)
		targetCount := notificationPolicyMetadataInt(rule, model.MetadataInhibitionTargetMatcherCount)
		sourceBroad := notificationPolicyMetadataInt(rule, model.MetadataInhibitionSourceBroadCount)
		targetBroad := notificationPolicyMetadataInt(rule, model.MetadataInhibitionTargetBroadCount)
		if sourceCount > 0 && targetCount > 0 && sourceBroad == 0 && targetBroad == 0 {
			continue
		}
		evidence := fmt.Sprintf("inhibition rule has %d source matchers and %d target matchers; broad source=%d target=%d", sourceCount, targetCount, sourceBroad, targetBroad)
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), rule.ID), Type: "BroadInhibitionRule", Severity: model.SeverityCritical,
			Resource: model.ResourceRef{ID: rule.ID, Type: rule.Type, Name: rule.Name}, Evidence: []string{evidence},
			Recommendation: "为 source 和 target 配置明确的 alertname、severity、service、team、cluster 或 namespace matcher，移除 `.*`/`.+` 全匹配正则，并用测试告警确认抑制范围。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(), "source_matcher_count": strconv.Itoa(sourceCount), "target_matcher_count": strconv.Itoa(targetCount),
				"source_broad_count": strconv.Itoa(sourceBroad), "target_broad_count": strconv.Itoa(targetBroad),
			},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func isActiveInhibitionRule(resource model.Resource) bool {
	return resource.Type == model.ResourceTypeInhibitionRule && resource.Status == model.ResourceStatusActive &&
		(resource.Source.System == "alertmanager" || resource.Source.System == "grafana")
}
