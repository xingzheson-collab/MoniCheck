package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const OrphanAlertAnalyzerID = "builtin.orphan_alert"

type OrphanAlertAnalyzer struct{}

func NewOrphanAlertAnalyzer() *OrphanAlertAnalyzer {
	return &OrphanAlertAnalyzer{}
}

func (a *OrphanAlertAnalyzer) ID() string {
	return OrphanAlertAnalyzerID
}

func (a *OrphanAlertAnalyzer) Name() string {
	return "Orphan Alert"
}

func (a *OrphanAlertAnalyzer) Version() string {
	return "0.1.0"
}

func (a *OrphanAlertAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *OrphanAlertAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alertRules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, alertRule := range alertRules {
		if alertRule.Status != model.ResourceStatusActive || isDisabledAlert(alertRule) {
			continue
		}
		if hasMetricReference(analysis.Graph.Outgoing(alertRule.ID), analysis.Graph) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alertRule.ID),
			Type:     "OrphanAlert",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alertRule.ID,
				Type: alertRule.Type,
				Name: alertRule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alert rule %q has no metric dependency relationship", alertRule.Name),
			},
			Recommendation: "确认告警规则是否仍应保留；如果 PromQL 无法解析出指标引用，建议修正规则或标记为外部依赖。",
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

func hasMetricReference(relationships []model.Relationship, resourceGraph interface {
	Resource(id string) (model.Resource, bool)
}) bool {
	for _, relationship := range relationships {
		switch relationship.Type {
		case model.RelationshipUses, model.RelationshipReferences, model.RelationshipDependsOn:
		default:
			continue
		}

		resource, ok := resourceGraph.Resource(relationship.ToID)
		if ok && resource.Type == model.ResourceTypeMetric {
			return true
		}
	}
	return false
}
