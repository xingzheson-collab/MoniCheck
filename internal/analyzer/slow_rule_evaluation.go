package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
)

const SlowRuleEvaluationAnalyzerID = "builtin.slow_rule_evaluation"

const defaultSlowRuleEvaluationRatioThreshold = 0.8

type SlowRuleEvaluationAnalyzer struct{}

func NewSlowRuleEvaluationAnalyzer() *SlowRuleEvaluationAnalyzer {
	return &SlowRuleEvaluationAnalyzer{}
}

func (a *SlowRuleEvaluationAnalyzer) ID() string {
	return SlowRuleEvaluationAnalyzerID
}

func (a *SlowRuleEvaluationAnalyzer) Name() string {
	return "Slow Rule Evaluation"
}

func (a *SlowRuleEvaluationAnalyzer) Version() string {
	return "0.1.0"
}

func (a *SlowRuleEvaluationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *SlowRuleEvaluationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules, err := listRules(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	threshold := floatConfig(analysis.Config, "slow_rule_evaluation_ratio_threshold", defaultSlowRuleEvaluationRatioThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, rule := range rules {
		if !isActiveQueryResource(rule) {
			continue
		}
		interval, ok := parseRuleDuration(rule.Metadata[model.MetadataEvaluationInterval])
		if !ok {
			continue
		}
		evaluationTime, ok := parseRuleDuration(rule.Metadata[model.MetadataEvaluationTime])
		if !ok {
			continue
		}
		ratio := float64(evaluationTime) / float64(interval)
		if ratio < threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), rule.ID),
			Type:     "SlowRuleEvaluation",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   rule.ID,
				Type: rule.Type,
				Name: rule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("rule %q evaluation time is %s of %s interval (ratio %.2f, threshold %.2f)", rule.Name, evaluationTime, interval, ratio, threshold),
			},
			Recommendation: "优化该规则 PromQL、降低查询基数或调整规则分组间隔；规则执行时间接近评估间隔会导致告警和记录规则数据变旧。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"evaluation_time": evaluationTime.String(),
				"interval":        interval.String(),
				"ratio":           fmt.Sprintf("%.4f", ratio),
				"threshold":       fmt.Sprintf("%.4f", threshold),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func parseRuleDuration(raw string) (time.Duration, bool) {
	if raw == "" {
		return 0, false
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}
