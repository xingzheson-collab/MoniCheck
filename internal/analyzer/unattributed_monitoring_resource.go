package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UnattributedMonitoringResourceAnalyzerID = "builtin.unattributed_monitoring_resource"

var monitoringServiceIdentityKeys = []string{
	model.MetadataService,
	"service_name",
	"service.name",
	"app",
	"application",
	"component",
	"app.kubernetes.io/name",
	"k8s_app",
}

type UnattributedMonitoringResourceAnalyzer struct{}

func NewUnattributedMonitoringResourceAnalyzer() *UnattributedMonitoringResourceAnalyzer {
	return &UnattributedMonitoringResourceAnalyzer{}
}

func (a *UnattributedMonitoringResourceAnalyzer) ID() string {
	return UnattributedMonitoringResourceAnalyzerID
}

func (a *UnattributedMonitoringResourceAnalyzer) Name() string {
	return "Unattributed Monitoring Resource"
}

func (a *UnattributedMonitoringResourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnattributedMonitoringResourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeAlertRule,
		model.ResourceTypeDashboard,
		model.ResourceTypeRecordingRule,
	}
}

func (a *UnattributedMonitoringResourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.Graph == nil {
		return nil, nil
	}

	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, resource := range resources {
		if !isServiceAttributionCandidate(resource) {
			continue
		}
		if hasServiceIdentity(resource) || hasServiceRelationship(resource.ID, analysis) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "UnattributedMonitoringResource",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s %q has no service identity label or metadata", resource.Type, resource.Name),
				"resource has no BELONGS_TO relationship to a Service",
			},
			Recommendation: "为该监控资源补充 service、app、application 或 component 标签/元数据，使 MoniCheck 能建立业务服务归属并进行服务级影响分析。",
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

func isServiceAttributionCandidate(resource model.Resource) bool {
	if resource.Status != model.ResourceStatusActive {
		return false
	}
	if resource.Type == model.ResourceTypeAlertRule && isDisabledAlert(resource) {
		return false
	}
	switch resource.Type {
	case model.ResourceTypeAlertRule, model.ResourceTypeDashboard, model.ResourceTypeRecordingRule:
		return true
	default:
		return false
	}
}

func hasServiceIdentity(resource model.Resource) bool {
	for _, key := range monitoringServiceIdentityKeys {
		if strings.TrimSpace(resource.Labels[key]) != "" || strings.TrimSpace(resource.Metadata[key]) != "" {
			return true
		}
	}
	return false
}

func hasServiceRelationship(resourceID string, analysis Context) bool {
	for _, relationship := range analysis.Graph.Outgoing(resourceID) {
		if relationship.Type != model.RelationshipBelongsTo {
			continue
		}
		target, ok := analysis.Graph.Resource(relationship.ToID)
		if ok && target.Type == model.ResourceTypeService && target.Status == model.ResourceStatusActive {
			return true
		}
	}
	return false
}
