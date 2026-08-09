package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const SLOObjectiveQualityAnalyzerID = "builtin.slo_objective_quality"

type SLOObjectiveQualityAnalyzer struct{}

func NewSLOObjectiveQualityAnalyzer() *SLOObjectiveQualityAnalyzer {
	return &SLOObjectiveQualityAnalyzer{}
}
func (a *SLOObjectiveQualityAnalyzer) ID() string      { return SLOObjectiveQualityAnalyzerID }
func (a *SLOObjectiveQualityAnalyzer) Name() string    { return "SLO Objective Quality" }
func (a *SLOObjectiveQualityAnalyzer) Version() string { return "0.1.0" }
func (a *SLOObjectiveQualityAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

type sloObjectiveGroup struct {
	name  string
	rules []model.Resource
}

func (a *SLOObjectiveQualityAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_slo_objective_issues", nil))
	groups := make(map[string]*sloObjectiveGroup)
	for _, resource := range resources {
		if !activeSLORule(resource) {
			continue
		}
		sloName := strings.TrimSpace(resource.Metadata[model.MetadataSLOName])
		if sloName == "" {
			continue
		}
		key := strings.Join([]string{
			strings.ToLower(strings.TrimSpace(resource.Source.System)),
			strings.ToLower(strings.TrimSpace(resource.Source.Instance)),
			strings.ToLower(sloName),
		}, "\x00")
		if groups[key] == nil {
			groups[key] = &sloObjectiveGroup{name: sloName}
		}
		groups[key].rules = append(groups[key].rules, resource)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, key := range keys {
		group := groups[key]
		if allowed[strings.ToLower(group.name)] {
			continue
		}
		sort.Slice(group.rules, func(i, j int) bool { return group.rules[i].ID < group.rules[j].ID })
		rawValues := make(map[string]bool)
		normalizedValues := make(map[string]bool)
		invalidValues := make(map[string]bool)
		for _, resource := range group.rules {
			raw := strings.TrimSpace(resource.Metadata[model.MetadataSLOObjective])
			if raw == "" {
				continue
			}
			rawValues[raw] = true
			if normalized, ok := model.NormalizeSLOObjective(raw); ok {
				normalizedValues[normalized] = true
			} else {
				invalidValues[raw] = true
			}
		}
		findingType, severity, evidence, recommendation := sloObjectiveIssue(group.name, rawValues, normalizedValues, invalidValues)
		if findingType == "" {
			continue
		}
		raw := mapKeys(rawValues)
		normalized := mapKeys(normalizedValues)
		invalid := mapKeys(invalidValues)
		resource := group.rules[0]
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), key),
			Type:           findingType,
			Severity:       severity,
			Category:       model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       evidence,
			Recommendation: recommendation,
			Metadata: map[string]string{
				"analyzer_id":                 a.ID(),
				"slo_name":                    group.name,
				"rule_count":                  strconv.Itoa(len(group.rules)),
				"objective_values":            strings.Join(raw, ","),
				"normalized_objective_values": strings.Join(normalized, ","),
				"invalid_objective_values":    strings.Join(invalid, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func sloObjectiveIssue(name string, raw map[string]bool, normalized map[string]bool, invalid map[string]bool) (string, model.Severity, []string, string) {
	if len(raw) == 0 {
		return "MissingSLOObjective", model.SeverityWarning,
			[]string{fmt.Sprintf("SLO %q has no objective on any active normalized rule", name)},
			"为该 SLO 补充明确 objective，并在同组 Recording Rule 与 AlertRule 上保持一致；可以使用 99.9、99.9% 或 0.999。"
	}
	if len(invalid) > 0 {
		return "InvalidSLOObjective", model.SeverityCritical,
			[]string{fmt.Sprintf("SLO %q contains invalid objective value(s): %s", name, strings.Join(mapKeys(invalid), ", "))},
			"将 objective 修正为大于 0 且小于 100% 的有限数值，例如 99.9、99.9% 或 0.999，并统一所有同组规则。"
	}
	if len(normalized) > 1 {
		return "InconsistentSLOObjective", model.SeverityCritical,
			[]string{fmt.Sprintf("SLO %q resolves to conflicting objectives: %s", name, strings.Join(mapKeys(normalized), ", "))},
			"统一该 SLO 所有 Recording Rule 与 AlertRule 的 objective，避免错误预算计算和燃尽率告警采用不同目标。"
	}
	return "", "", nil, ""
}
