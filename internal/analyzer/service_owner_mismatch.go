package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const ServiceOwnerMismatchAnalyzerID = "builtin.service_owner_mismatch"

type ServiceOwnerMismatchAnalyzer struct{}

func NewServiceOwnerMismatchAnalyzer() *ServiceOwnerMismatchAnalyzer {
	return &ServiceOwnerMismatchAnalyzer{}
}

func (a *ServiceOwnerMismatchAnalyzer) ID() string {
	return ServiceOwnerMismatchAnalyzerID
}

func (a *ServiceOwnerMismatchAnalyzer) Name() string {
	return "Service Owner Mismatch"
}

func (a *ServiceOwnerMismatchAnalyzer) Version() string {
	return "0.1.0"
}

func (a *ServiceOwnerMismatchAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeMetric,
		model.ResourceTypeDashboard,
		model.ResourceTypePanel,
		model.ResourceTypeAlert,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeDatasource,
		model.ResourceTypeTarget,
		model.ResourceTypeExporter,
		model.ResourceTypeJob,
		model.ResourceTypeInstance,
		model.ResourceTypeTraceService,
		model.ResourceTypeTraceOperation,
	}
}

func (a *ServiceOwnerMismatchAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.Graph == nil {
		return nil, nil
	}
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}

	ownerKeys := stringSliceConfig(analysis.Config, "owner_keys", defaultOwnerKeys)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, resource := range resources {
		if !isServiceOwnerMismatchCandidate(resource) {
			continue
		}
		for _, relationship := range analysis.Graph.Outgoing(resource.ID) {
			if relationship.Type != model.RelationshipBelongsTo {
				continue
			}
			service, ok := analysis.Graph.Resource(relationship.ToID)
			if !ok || service.Type != model.ResourceTypeService || service.Status != model.ResourceStatusActive {
				continue
			}
			mismatches := ownershipMismatches(resource, service, ownerKeys)
			if len(mismatches) == 0 {
				continue
			}
			findings = append(findings, model.Finding{
				ID:       model.StableID(a.ID(), resource.ID, service.ID),
				Type:     "ServiceOwnerMismatch",
				Severity: model.SeverityWarning,
				Resource: model.ResourceRef{
					ID:   resource.ID,
					Type: resource.Type,
					Name: resource.Name,
				},
				Evidence: []string{
					fmt.Sprintf("%s %q belongs to service %q but ownership metadata differs", resource.Type, resource.Name, service.Name),
					strings.Join(mismatches, "; "),
				},
				Recommendation: "统一该监控资源与业务服务的 owner/team/squad/maintainer/responsible 元数据；如果确实由不同团队维护，请明确拆分服务归属或补充例外策略。",
				Metadata: map[string]string{
					"analyzer_id": a.ID(),
					"service_id":  service.ID,
					"service":     service.Name,
					"mismatches":  strings.Join(mismatches, "; "),
				},
				Status:    model.FindingStatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}
	return findings, nil
}

func isServiceOwnerMismatchCandidate(resource model.Resource) bool {
	if resource.Status != model.ResourceStatusActive {
		return false
	}
	if resource.Type == model.ResourceTypeAlertRule && isDisabledAlert(resource) {
		return false
	}
	switch resource.Type {
	case model.ResourceTypeMetric,
		model.ResourceTypeDashboard,
		model.ResourceTypePanel,
		model.ResourceTypeAlert,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeDatasource,
		model.ResourceTypeTarget,
		model.ResourceTypeExporter,
		model.ResourceTypeJob,
		model.ResourceTypeInstance,
		model.ResourceTypeTraceService,
		model.ResourceTypeTraceOperation:
		return true
	default:
		return false
	}
}

func ownershipMismatches(resource model.Resource, service model.Resource, ownerKeys []string) []string {
	mismatches := make([]string, 0)
	for _, key := range ownerKeys {
		resourceValue := ownershipValue(resource, key)
		serviceValue := ownershipValue(service, key)
		if resourceValue == "" || serviceValue == "" {
			continue
		}
		if strings.EqualFold(resourceValue, serviceValue) {
			continue
		}
		mismatches = append(mismatches, fmt.Sprintf("%s resource=%q service=%q", key, resourceValue, serviceValue))
	}
	return mismatches
}

func ownershipValue(resource model.Resource, key string) string {
	if value := strings.TrimSpace(resource.Metadata[key]); value != "" {
		return value
	}
	return strings.TrimSpace(resource.Labels[key])
}
