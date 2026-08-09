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

const (
	SLOWindowCoverageAnalyzerID = "builtin.slo_window_coverage"
	defaultSLOMinimumWindows    = 2
	defaultSLOShortWindowMax    = time.Hour
	defaultSLOLongWindowMin     = 6 * time.Hour
)

type SLOWindowCoverageAnalyzer struct{}

func NewSLOWindowCoverageAnalyzer() *SLOWindowCoverageAnalyzer { return &SLOWindowCoverageAnalyzer{} }
func (a *SLOWindowCoverageAnalyzer) ID() string                { return SLOWindowCoverageAnalyzerID }
func (a *SLOWindowCoverageAnalyzer) Name() string              { return "SLO Window Coverage" }
func (a *SLOWindowCoverageAnalyzer) Version() string           { return "0.1.0" }
func (a *SLOWindowCoverageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

type sloWindowGroup struct {
	name  string
	rules []model.Resource
}

func (a *SLOWindowCoverageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	minimumWindows := intConfig(analysis.Config, "slo_minimum_window_count", defaultSLOMinimumWindows)
	shortWindowMax := durationConfig(analysis.Config, "slo_short_window_max", defaultSLOShortWindowMax)
	longWindowMin := durationConfig(analysis.Config, "slo_long_window_min", defaultSLOLongWindowMin)
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_slo_window_issues", nil))
	groups := make(map[string]*sloWindowGroup)
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
			groups[key] = &sloWindowGroup{name: sloName}
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
		rawWindows := make(map[string]bool)
		validWindows := make(map[string]time.Duration)
		invalidWindows := make(map[string]bool)
		shortCount := 0
		longCount := 0
		for _, resource := range group.rules {
			raw := strings.TrimSpace(resource.Metadata[model.MetadataSLOWindow])
			if raw == "" {
				continue
			}
			rawWindows[raw] = true
			normalized, duration, ok := model.NormalizeSLOWindow(raw)
			if !ok {
				invalidWindows[raw] = true
				continue
			}
			validWindows[normalized] = duration
		}
		if len(rawWindows) == 0 {
			continue
		}
		for _, duration := range validWindows {
			if duration <= shortWindowMax {
				shortCount++
			}
			if duration >= longWindowMin {
				longCount++
			}
		}
		findingType, severity, evidence, recommendation := sloWindowIssue(group.name, validWindows, invalidWindows, minimumWindows, shortWindowMax, longWindowMin, shortCount, longCount)
		if findingType == "" {
			continue
		}
		valid := sortedDurationKeys(validWindows)
		invalid := mapKeys(invalidWindows)
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
				"analyzer_id":           a.ID(),
				"slo_name":              group.name,
				"window_values":         strings.Join(valid, ","),
				"invalid_window_values": strings.Join(invalid, ","),
				"window_count":          strconv.Itoa(len(validWindows)),
				"short_window_count":    strconv.Itoa(shortCount),
				"long_window_count":     strconv.Itoa(longCount),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func sloWindowIssue(name string, valid map[string]time.Duration, invalid map[string]bool, minimum int, shortMax time.Duration, longMin time.Duration, shortCount int, longCount int) (string, model.Severity, []string, string) {
	if len(invalid) > 0 {
		return "InvalidSLOWindow", model.SeverityCritical,
			[]string{fmt.Sprintf("SLO %q contains invalid window value(s): %s", name, strings.Join(mapKeys(invalid), ", "))},
			"将 window 修正为可解析的正 duration，例如 5m、1h、6h、3d，并统一同组规则的窗口标签。"
	}
	if len(valid) < minimum {
		return "InsufficientSLOWindows", model.SeverityWarning,
			[]string{fmt.Sprintf("SLO %q has %d distinct valid window(s); minimum is %d", name, len(valid), minimum)},
			"为该 SLO 增加多个独立评估窗口，至少同时覆盖快速燃尽和慢速燃尽，避免单窗口告警漏掉不同故障速度。"
	}
	if shortCount == 0 || longCount == 0 {
		return "IncompleteSLOWindowCoverage", model.SeverityWarning,
			[]string{fmt.Sprintf("SLO %q window coverage has short=%d (<=%s), long=%d (>=%s)", name, shortCount, shortMax, longCount, longMin)},
			"补齐快速和慢速燃尽窗口；默认至少包含一个不超过 1h 的窗口和一个不短于 6h 的窗口。"
	}
	return "", "", nil, ""
}

func sortedDurationKeys(values map[string]time.Duration) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if values[keys[i]] == values[keys[j]] {
			return keys[i] < keys[j]
		}
		return values[keys[i]] < values[keys[j]]
	})
	return keys
}
