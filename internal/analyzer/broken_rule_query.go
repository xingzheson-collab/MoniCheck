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
		findingType, severity, evidence := ruleQueryEvidence(rule, analysis)
		if findingType == "" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), findingType, rule.ID),
			Type:     findingType,
			Severity: severity,
			Resource: model.ResourceRef{
				ID:   rule.ID,
				Type: rule.Type,
				Name: rule.Name,
			},
			Evidence:       evidence,
			Recommendation: ruleQueryRecommendation(findingType),
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

func ruleQueryEvidence(rule model.Resource, analysis Context) (string, model.Severity, []string) {
	query := strings.TrimSpace(rule.Metadata[model.MetadataPromQL])
	if query == "" {
		return "MissingRuleQuery", model.SeverityWarning, []string{fmt.Sprintf("%s %q has no PromQL query metadata", ruleQueryResourceKind(rule), rule.Name)}
	}
	if len(connector.ExtractPromQLMetricNames(query)) == 0 {
		return "UnresolvedRuleQueryMetric", model.SeverityWarning, []string{fmt.Sprintf("%s %q query has no resolvable metric reference", ruleQueryResourceKind(rule), rule.Name)}
	}
	if analysis.Graph == nil {
		return "", "", nil
	}
	for _, relationship := range analysis.Graph.Outgoing(rule.ID) {
		if relationship.Type != model.RelationshipUses {
			continue
		}
		target, ok := analysis.Graph.Resource(relationship.ToID)
		if !ok {
			if relationship.Metadata[model.MetadataMetricInventoryBinding] == "EXACT" {
				if rule.Type == model.ResourceTypeAlertRule {
					return "AlertRuleMetricNotCollected", model.SeverityCritical, []string{fmt.Sprintf("alert rule %q references a metric absent from its explicitly bound Prometheus inventory", rule.Name)}
				}
				return "RecordingRuleInputNotCollected", model.SeverityWarning, []string{fmt.Sprintf("recording rule %q references an input metric absent from its explicitly bound Prometheus inventory", rule.Name)}
			}
			return "UnresolvedRuleQueryMetric", model.SeverityWarning, []string{fmt.Sprintf("%s %q uses a resource that is not visible in the current inventory", ruleQueryResourceKind(rule), rule.Name)}
		}
		if target.Type != model.ResourceTypeMetric {
			return "UnresolvedRuleQueryMetric", model.SeverityWarning, []string{fmt.Sprintf("%s %q uses non-metric resource %q of type %s", ruleQueryResourceKind(rule), rule.Name, target.Name, target.Type)}
		}
	}
	return "", "", nil
}

func ruleQueryRecommendation(findingType string) string {
	switch findingType {
	case "AlertRuleMetricNotCollected":
		return "Restore collection for the bound metric or correct the alert expression, then prove the rule evaluates against current data and send a controlled notification test."
	case "RecordingRuleInputNotCollected":
		return "Restore the bound input metric or correct the recording rule expression, then verify the output series and every dependent alert."
	default:
		return "Inspect the rule query and confirm that its language, datasource attribution, and metric dependencies can be evaluated."
	}
}

func ruleQueryResourceKind(rule model.Resource) string {
	if rule.Type == model.ResourceTypeRecordingRule {
		return "recording rule"
	}
	return "alert rule"
}
