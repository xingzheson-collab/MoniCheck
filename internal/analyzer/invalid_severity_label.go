package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
)

const InvalidSeverityLabelAnalyzerID = "builtin.invalid_severity_label"

var defaultAllowedSeverityLabels = []string{"critical", "warning", "info"}

type InvalidSeverityLabelAnalyzer struct{}

func NewInvalidSeverityLabelAnalyzer() *InvalidSeverityLabelAnalyzer {
	return &InvalidSeverityLabelAnalyzer{}
}

func (a *InvalidSeverityLabelAnalyzer) ID() string {
	return InvalidSeverityLabelAnalyzerID
}

func (a *InvalidSeverityLabelAnalyzer) Name() string {
	return "Invalid Severity Label"
}

func (a *InvalidSeverityLabelAnalyzer) Version() string {
	return "0.1.0"
}

func (a *InvalidSeverityLabelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeAlert}
}

func (a *InvalidSeverityLabelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listSeverityLabelResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	allowedValues := severitySet(stringSliceConfig(analysis.Config, "allowed_severity_labels", defaultAllowedSeverityLabels))
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Type == model.ResourceTypeAlertRule && (resource.Status != model.ResourceStatusActive || isDisabledAlert(resource)) {
			continue
		}
		if resource.Type == model.ResourceTypeAlert && !isActiveRuntimeAlert(resource) {
			continue
		}
		severity, ok := severityValue(resource)
		if !ok {
			continue
		}
		normalized := strings.ToLower(severity)
		if allowedValues[normalized] {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID, normalized),
			Type:     "InvalidSeverityLabel",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s %q has unsupported severity label %q", severityResourceKind(resource), resource.Name, severity),
			},
			Recommendation: "将告警或告警规则的 severity 标签调整为团队允许的标准值，避免告警路由、报表聚合和优先级判断出现分歧。",
			Metadata: map[string]string{
				"analyzer_id":      a.ID(),
				"severity":         severity,
				"allowed_severity": strings.Join(sortedSeverityValues(allowedValues), ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func severityValue(alertRule model.Resource) (string, bool) {
	if value := strings.TrimSpace(alertRule.Labels["severity"]); value != "" {
		return value, true
	}
	if value := strings.TrimSpace(alertRule.Metadata["severity"]); value != "" {
		return value, true
	}
	return "", false
}

func severitySet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		result[value] = true
	}
	return result
}

func sortedSeverityValues(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
