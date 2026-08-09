package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
)

const StaleRuleEvaluationAnalyzerID = "builtin.stale_rule_evaluation"

const (
	defaultStaleRuleEvaluationGraceFactor = 3.0
	defaultStaleRuleEvaluationThreshold   = 15 * time.Minute
)

type StaleRuleEvaluationAnalyzer struct{}

func NewStaleRuleEvaluationAnalyzer() *StaleRuleEvaluationAnalyzer {
	return &StaleRuleEvaluationAnalyzer{}
}

func (a *StaleRuleEvaluationAnalyzer) ID() string {
	return StaleRuleEvaluationAnalyzerID
}

func (a *StaleRuleEvaluationAnalyzer) Name() string {
	return "Stale Rule Evaluation"
}

func (a *StaleRuleEvaluationAnalyzer) Version() string {
	return "0.1.0"
}

func (a *StaleRuleEvaluationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *StaleRuleEvaluationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := listRules(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	graceFactor := floatConfig(analysis.Config, "stale_rule_evaluation_grace_factor", defaultStaleRuleEvaluationGraceFactor)
	fallbackThreshold := durationConfig(analysis.Config, "stale_rule_evaluation_threshold", defaultStaleRuleEvaluationThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, rule := range rules {
		if !isActiveQueryResource(rule) {
			continue
		}
		lastEvaluation, ok := parseRuleEvaluationTime(rule.Metadata[model.MetadataLastEvaluation])
		if !ok {
			continue
		}
		threshold := staleRuleEvaluationThreshold(rule, graceFactor, fallbackThreshold)
		age := now.Sub(lastEvaluation)
		if age <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), rule.ID),
			Type:     "StaleRuleEvaluation",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   rule.ID,
				Type: rule.Type,
				Name: rule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("rule %q was last evaluated at %s, age is %s and threshold is %s", rule.Name, lastEvaluation.Format(time.RFC3339), age.Round(time.Second), threshold),
			},
			Recommendation: "检查 Prometheus rule group 是否仍在调度、规则文件是否加载成功，以及查询是否阻塞；规则长期未评估会导致告警和记录指标失真。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"last_evaluation": lastEvaluation.Format(time.RFC3339),
				"age":             age.Round(time.Second).String(),
				"threshold":       threshold.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func staleRuleEvaluationThreshold(rule model.Resource, graceFactor float64, fallback time.Duration) time.Duration {
	interval, ok := parseRuleDuration(rule.Metadata[model.MetadataEvaluationInterval])
	if !ok {
		return fallback
	}
	threshold := time.Duration(float64(interval) * graceFactor)
	if threshold <= 0 {
		return fallback
	}
	return threshold
}

func parseRuleEvaluationTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
