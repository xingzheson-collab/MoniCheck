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

const SLOWithoutAlertAnalyzerID = "builtin.slo_without_alert"

type SLOWithoutAlertAnalyzer struct{}

func NewSLOWithoutAlertAnalyzer() *SLOWithoutAlertAnalyzer { return &SLOWithoutAlertAnalyzer{} }
func (a *SLOWithoutAlertAnalyzer) ID() string              { return SLOWithoutAlertAnalyzerID }
func (a *SLOWithoutAlertAnalyzer) Name() string            { return "SLO Without Alert" }
func (a *SLOWithoutAlertAnalyzer) Version() string         { return "0.1.0" }
func (a *SLOWithoutAlertAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

type sloRuleGroup struct {
	name       string
	recordings []model.Resource
	alertCount int
	objectives map[string]bool
}

func (a *SLOWithoutAlertAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_slos_without_alert", nil))
	groups := make(map[string]*sloRuleGroup)
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
		group := groups[key]
		if group == nil {
			group = &sloRuleGroup{name: sloName, objectives: make(map[string]bool)}
			groups[key] = group
		}
		if objective := strings.TrimSpace(resource.Metadata[model.MetadataSLOObjective]); objective != "" {
			group.objectives[objective] = true
		}
		if resource.Type == model.ResourceTypeRecordingRule {
			group.recordings = append(group.recordings, resource)
		} else if resource.Type == model.ResourceTypeAlertRule {
			group.alertCount++
		}
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
		if len(group.recordings) == 0 || group.alertCount > 0 || allowed[strings.ToLower(group.name)] {
			continue
		}
		sort.Slice(group.recordings, func(i, j int) bool { return group.recordings[i].ID < group.recordings[j].ID })
		resource := group.recordings[0]
		objectives := mapKeys(group.objectives)
		objectiveText := "not declared"
		if len(objectives) > 0 {
			objectiveText = strings.Join(objectives, ",")
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), key),
			Type:     "SLOWithoutAlert",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{
				fmt.Sprintf("SLO %q has %d active recording rule(s) but no active SLO alert rule", group.name, len(group.recordings)),
				fmt.Sprintf("normalized objective: %s", objectiveText),
			},
			Recommendation: "为该 SLO 增加多窗口、多燃尽率告警，并保留相同的 slo/service/objective 标签；至少覆盖快速燃尽和慢速燃尽场景，避免只记录错误预算而无法触发值班响应。",
			Metadata: map[string]string{
				"analyzer_id":          a.ID(),
				"slo_name":             group.name,
				"slo_objectives":       strings.Join(objectives, ","),
				"recording_rule_count": strconv.Itoa(len(group.recordings)),
				"alert_rule_count":     "0",
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func mapKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
