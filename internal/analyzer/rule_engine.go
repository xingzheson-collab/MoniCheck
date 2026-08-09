package analyzer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/rule"
	"monicheck/internal/storage"
)

const RuleEngineAnalyzerID = "builtin.rule_engine"

type RuleEngineAnalyzer struct {
	mu    sync.RWMutex
	rules []rule.Rule
}

func NewRuleEngineAnalyzer(rules []rule.Rule) *RuleEngineAnalyzer {
	return &RuleEngineAnalyzer{rules: append([]rule.Rule(nil), rules...)}
}

func (a *RuleEngineAnalyzer) Rules() []rule.Rule {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]rule.Rule(nil), a.rules...)
}

func (a *RuleEngineAnalyzer) ReloadRules(rules []rule.Rule) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = append([]rule.Rule(nil), rules...)
}

func (a *RuleEngineAnalyzer) ID() string {
	return RuleEngineAnalyzerID
}

func (a *RuleEngineAnalyzer) Name() string {
	return "Rule Engine"
}

func (a *RuleEngineAnalyzer) Version() string {
	return "0.1.0"
}

func (a *RuleEngineAnalyzer) InputTypes() []model.ResourceType {
	rules := a.Rules()
	types := make([]model.ResourceType, 0)
	seen := make(map[model.ResourceType]bool)
	for _, item := range rules {
		for _, resourceType := range item.Scope {
			if seen[resourceType] {
				continue
			}
			seen[resourceType] = true
			types = append(types, resourceType)
		}
	}
	return types
}

func (a *RuleEngineAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	rules := a.Rules()
	if len(rules) == 0 {
		return nil, nil
	}
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, item := range rules {
		for _, resource := range resources {
			if !rule.InScope(item, resource) {
				continue
			}
			evaluation, err := rule.Evaluate(item, resource, analysis.Graph)
			if err != nil {
				return nil, fmt.Errorf("evaluate rule %s for resource %s: %w", item.ID, resource.ID, err)
			}
			if !evaluation.Matched {
				continue
			}
			findings = append(findings, a.finding(item, resource, evaluation, now))
		}
	}
	return findings, nil
}

func (a *RuleEngineAnalyzer) finding(item rule.Rule, resource model.Resource, evaluation rule.Evaluation, now time.Time) model.Finding {
	metadata := map[string]string{
		"analyzer_id":  a.ID(),
		"rule_id":      item.ID,
		"rule_version": item.Version,
		"expression":   item.Condition.Expression,
	}
	for key, value := range item.Metadata {
		metadata[key] = value
	}
	recommendation := item.Recommendation
	if recommendation == "" {
		recommendation = "根据规则定义处理该治理违规，必要时补充资源元数据、修复依赖关系或调整采集与告警配置。"
	}
	return model.Finding{
		ID:       model.StableID(a.ID(), item.ID, resource.ID),
		Type:     item.FindingType,
		Severity: item.Severity,
		Category: rule.Category(item.Type),
		Resource: model.ResourceRef{
			ID:   resource.ID,
			Type: resource.Type,
			Name: resource.Name,
		},
		Evidence:       []string{evaluation.Reason},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}
