package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const RequiredLabelsAnalyzerID = "builtin.required_labels"

type RequiredLabelsAnalyzer struct{}

func NewRequiredLabelsAnalyzer() *RequiredLabelsAnalyzer {
	return &RequiredLabelsAnalyzer{}
}

func (a *RequiredLabelsAnalyzer) ID() string {
	return RequiredLabelsAnalyzerID
}

func (a *RequiredLabelsAnalyzer) Name() string {
	return "Required Labels"
}

func (a *RequiredLabelsAnalyzer) Version() string {
	return "0.1.0"
}

func (a *RequiredLabelsAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeMetric,
		model.ResourceTypeDashboard,
		model.ResourceTypePanel,
		model.ResourceTypeDatasource,
		model.ResourceTypeAlert,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeTarget,
	}
}

func (a *RequiredLabelsAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	requiredLabels := stringSliceConfig(analysis.Config, "required_resource_labels", nil)
	if len(requiredLabels) == 0 {
		return nil, nil
	}

	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	eligibleTypes := requiredLabelResourceTypes(a.InputTypes())
	for _, resource := range resources {
		if !isRequiredLabelResource(resource, eligibleTypes) {
			continue
		}
		missing := missingLabels(resource, requiredLabels)
		if len(missing) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID, strings.Join(missing, ",")),
			Type:     "MissingRequiredLabel",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s %q is missing required labels: %s", resource.Type, resource.Name, strings.Join(missing, ", ")),
			},
			Recommendation: "为资源补充必需标签，确保治理报告、归属分派和生命周期策略可以按组织维度聚合。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"missing_labels":  strings.Join(missing, ","),
				"required_labels": strings.Join(requiredLabels, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func requiredLabelResourceTypes(inputTypes []model.ResourceType) map[model.ResourceType]bool {
	types := make(map[model.ResourceType]bool, len(inputTypes))
	for _, resourceType := range inputTypes {
		types[resourceType] = true
	}
	return types
}

func isRequiredLabelResource(resource model.Resource, eligibleTypes map[model.ResourceType]bool) bool {
	if !eligibleTypes[resource.Type] {
		return false
	}
	switch resource.Type {
	case model.ResourceTypeAlert:
		return isActiveRuntimeAlert(resource)
	case model.ResourceTypeAlertRule:
		return resource.Status == model.ResourceStatusActive && !isDisabledAlert(resource)
	default:
		return resource.Status == model.ResourceStatusActive
	}
}

func missingLabels(resource model.Resource, requiredLabels []string) []string {
	missing := make([]string, 0)
	for _, label := range requiredLabels {
		if strings.TrimSpace(resource.Labels[label]) != "" || strings.TrimSpace(resource.Metadata[label]) != "" {
			continue
		}
		missing = append(missing, label)
	}
	return missing
}
