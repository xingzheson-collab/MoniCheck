package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const NoActiveAlertInstanceAnalyzerID = "builtin.no_active_alert_instance"

type NoActiveAlertInstanceAnalyzer struct{}

func NewNoActiveAlertInstanceAnalyzer() *NoActiveAlertInstanceAnalyzer {
	return &NoActiveAlertInstanceAnalyzer{}
}

func (a *NoActiveAlertInstanceAnalyzer) ID() string {
	return NoActiveAlertInstanceAnalyzerID
}

func (a *NoActiveAlertInstanceAnalyzer) Name() string {
	return "No Active Alert Instance"
}

func (a *NoActiveAlertInstanceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *NoActiveAlertInstanceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *NoActiveAlertInstanceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alertRules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, alertRule := range alertRules {
		if alertRule.Status != model.ResourceStatusActive || isDisabledAlert(alertRule) {
			continue
		}
		if hasActiveAlertInstance(alertRule.ID, analysis.Graph.Incoming(alertRule.ID), analysis.Graph) {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alertRule.ID),
			Type:     "NoActiveAlertInstance",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   alertRule.ID,
				Type: alertRule.Type,
				Name: alertRule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alert rule %q has no active alert instance relationship", alertRule.Name),
			},
			Recommendation: "确认该告警规则是否长期没有触发；如果业务已下线或规则过时，可以降低优先级、归档或删除。",
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

func hasActiveAlertInstance(ruleID string, relationships []model.Relationship, resourceGraph interface {
	Resource(id string) (model.Resource, bool)
}) bool {
	for _, relationship := range relationships {
		if relationship.Type != model.RelationshipReferences || relationship.ToID != ruleID {
			continue
		}
		resource, ok := resourceGraph.Resource(relationship.FromID)
		if !ok || resource.Type != model.ResourceTypeAlert {
			continue
		}
		state := strings.ToLower(strings.TrimSpace(resource.Metadata[model.MetadataAlertState]))
		if state == "" || state == "active" || state == "firing" || state == "pending" {
			return true
		}
	}
	return false
}
