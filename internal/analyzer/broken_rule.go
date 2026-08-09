package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const BrokenRuleAnalyzerID = "builtin.broken_rule"

type BrokenRuleAnalyzer struct{}

func NewBrokenRuleAnalyzer() *BrokenRuleAnalyzer {
	return &BrokenRuleAnalyzer{}
}

func (a *BrokenRuleAnalyzer) ID() string {
	return BrokenRuleAnalyzerID
}

func (a *BrokenRuleAnalyzer) Name() string {
	return "Broken Rule"
}

func (a *BrokenRuleAnalyzer) Version() string {
	return "0.1.0"
}

func (a *BrokenRuleAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *BrokenRuleAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := listRules(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, rule := range rules {
		if !isRuleEligibleForHealthDetection(rule) {
			continue
		}
		evidence := ruleEvidence(rule)
		if len(evidence) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), rule.ID),
			Type:     "BrokenRule",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   rule.ID,
				Type: rule.Type,
				Name: rule.Name,
			},
			Evidence:       evidence,
			Recommendation: "检查规则 PromQL、依赖指标、标签模板和规则管理平台中的执行状态。",
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

func listRules(ctx context.Context, resources storage.ResourceRepository) ([]model.Resource, error) {
	alertRules, err := resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	recordingRules, err := resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeRecordingRule})
	if err != nil {
		return nil, err
	}
	return append(alertRules, recordingRules...), nil
}

func ruleEvidence(rule model.Resource) []string {
	health := strings.TrimSpace(rule.Metadata[model.MetadataHealth])

	evidence := make([]string, 0, 2)
	if health != "" && !strings.EqualFold(health, "ok") {
		evidence = append(evidence, fmt.Sprintf("rule health is %q", health))
	}
	if rule.Status == model.ResourceStatusBroken && len(evidence) == 0 {
		evidence = append(evidence, "rule status is BROKEN")
	}
	return evidence
}

func isRuleEligibleForHealthDetection(rule model.Resource) bool {
	if rule.Status == model.ResourceStatusDeprecated || rule.Status == model.ResourceStatusDeleted {
		return false
	}
	if rule.Type == model.ResourceTypeAlertRule && isDisabledAlert(rule) {
		return false
	}
	return true
}
