package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/connector"
	"monicheck/internal/model"
)

const BrokenRuleQueryAnalyzerID = "builtin.broken_rule_query"

type BrokenRuleQueryAnalyzer struct{}

func NewBrokenRuleQueryAnalyzer() *BrokenRuleQueryAnalyzer {
	return &BrokenRuleQueryAnalyzer{}
}

func (a *BrokenRuleQueryAnalyzer) ID() string {
	return BrokenRuleQueryAnalyzerID
}

func (a *BrokenRuleQueryAnalyzer) Name() string {
	return "Broken Rule Query"
}

func (a *BrokenRuleQueryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *BrokenRuleQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *BrokenRuleQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := listRules(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, rule := range rules {
		if rule.Status != model.ResourceStatusActive || isDisabledAlert(rule) {
			continue
		}
		findingType, evidence := ruleQueryEvidence(rule, analysis)
		if findingType == "" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), findingType, rule.ID),
			Type:     findingType,
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   rule.ID,
				Type: rule.Type,
				Name: rule.Name,
			},
			Evidence:       evidence,
			Recommendation: "检查规则 PromQL 是否为空、是否引用了可解析的指标，并确认规则依赖关系指向有效 Metric 资源。",
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

func ruleQueryEvidence(rule model.Resource, analysis Context) (string, []string) {
	query := strings.TrimSpace(rule.Metadata[model.MetadataPromQL])
	if query == "" {
		return "MissingRuleQuery", []string{fmt.Sprintf("%s %q has no PromQL query metadata", ruleQueryResourceKind(rule), rule.Name)}
	}
	if len(connector.ExtractPromQLMetricNames(query)) == 0 {
		return "UnresolvedRuleQueryMetric", []string{fmt.Sprintf("%s %q query has no resolvable metric reference", ruleQueryResourceKind(rule), rule.Name)}
	}
	if analysis.Graph == nil {
		return "", nil
	}
	for _, relationship := range analysis.Graph.Outgoing(rule.ID) {
		if relationship.Type != model.RelationshipUses {
			continue
		}
		target, ok := analysis.Graph.Resource(relationship.ToID)
		if !ok {
			return "UnresolvedRuleQueryMetric", []string{fmt.Sprintf("%s %q uses missing resource %q", ruleQueryResourceKind(rule), rule.Name, relationship.ToID)}
		}
		if target.Type != model.ResourceTypeMetric {
			return "UnresolvedRuleQueryMetric", []string{fmt.Sprintf("%s %q uses non-metric resource %q of type %s", ruleQueryResourceKind(rule), rule.Name, target.Name, target.Type)}
		}
	}
	return "", nil
}

func ruleQueryResourceKind(rule model.Resource) string {
	if rule.Type == model.ResourceTypeRecordingRule {
		return "recording rule"
	}
	return "alert rule"
}
