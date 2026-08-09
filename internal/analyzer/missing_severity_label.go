package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const MissingSeverityLabelAnalyzerID = "builtin.missing_severity_label"

type MissingSeverityLabelAnalyzer struct{}

func NewMissingSeverityLabelAnalyzer() *MissingSeverityLabelAnalyzer {
	return &MissingSeverityLabelAnalyzer{}
}

func (a *MissingSeverityLabelAnalyzer) ID() string {
	return MissingSeverityLabelAnalyzerID
}

func (a *MissingSeverityLabelAnalyzer) Name() string {
	return "Missing Severity Label"
}

func (a *MissingSeverityLabelAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MissingSeverityLabelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeAlert}
}

func (a *MissingSeverityLabelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listSeverityLabelResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Type == model.ResourceTypeAlertRule && (resource.Status != model.ResourceStatusActive || isDisabledAlert(resource)) {
			continue
		}
		if resource.Type == model.ResourceTypeAlert && !isActiveRuntimeAlert(resource) {
			continue
		}
		if hasSeverity(resource) {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "MissingSeverityLabel",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s %q has no severity label", severityResourceKind(resource), resource.Name),
			},
			Recommendation: "为告警或告警规则补充 severity 标签，例如 critical、warning 或 info，便于分级路由、值班响应和治理报表聚合。",
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

func listSeverityLabelResources(ctx context.Context, resources storage.ResourceRepository) ([]model.Resource, error) {
	alertRules, err := resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	alerts, err := resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlert})
	if err != nil {
		return nil, err
	}
	return append(alertRules, alerts...), nil
}

func hasSeverity(resource model.Resource) bool {
	if strings.TrimSpace(resource.Labels["severity"]) != "" {
		return true
	}
	if strings.TrimSpace(resource.Metadata["severity"]) != "" {
		return true
	}
	return false
}

func severityResourceKind(resource model.Resource) string {
	if resource.Type == model.ResourceTypeAlert {
		return "alert"
	}
	return "alert rule"
}
