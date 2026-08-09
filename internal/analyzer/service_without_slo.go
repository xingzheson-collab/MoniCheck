package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const ServiceWithoutSLOAnalyzerID = "builtin.service_without_slo"

type ServiceWithoutSLOAnalyzer struct{}

func NewServiceWithoutSLOAnalyzer() *ServiceWithoutSLOAnalyzer {
	return &ServiceWithoutSLOAnalyzer{}
}

func (a *ServiceWithoutSLOAnalyzer) ID() string      { return ServiceWithoutSLOAnalyzerID }
func (a *ServiceWithoutSLOAnalyzer) Name() string    { return "Service Without SLO" }
func (a *ServiceWithoutSLOAnalyzer) Version() string { return "0.1.0" }

func (a *ServiceWithoutSLOAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService, model.ResourceTypeMetric, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *ServiceWithoutSLOAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.Graph == nil {
		return nil, nil
	}
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	availableSLORules := activeSLORuleCount(resources)
	if availableSLORules == 0 {
		return nil, nil
	}

	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_services_without_slo", nil))
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, service := range resources {
		if service.Type != model.ResourceTypeService || service.Status != model.ResourceStatusActive || allowedResource(service, allowed, model.MetadataService) {
			continue
		}
		members := serviceMembers(service.ID, analysis)
		metricCount := 0
		sloRuleCount := 0
		for _, member := range members {
			if member.Type == model.ResourceTypeMetric {
				metricCount++
			}
			if activeSLORule(member) {
				sloRuleCount++
			}
		}
		if metricCount == 0 || sloRuleCount > 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), service.ID),
			Type:     "ServiceWithoutSLO",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: service.ID, Type: service.Type, Name: service.Name},
			Evidence: []string{
				fmt.Sprintf("service %q has %d attributed metric(s) but no normalized SLO alert or recording rule", service.Name, metricCount),
				fmt.Sprintf("the current resource graph contains %d active SLO rule(s)", availableSLORules),
			},
			Recommendation: "为该服务定义可评审的 SLI/SLO，并通过带有明确 slo/objective 标签的 Recording Rule 与多窗口燃尽率告警关联到同一 service；如暂不纳入 SLO 管理，将服务加入例外名单并记录原因。",
			Metadata: map[string]string{
				"analyzer_id":         a.ID(),
				"metric_count":        strconv.Itoa(metricCount),
				"available_slo_rules": strconv.Itoa(availableSLORules),
				"service":             strings.TrimSpace(service.Name),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func activeSLORuleCount(resources []model.Resource) int {
	count := 0
	for _, resource := range resources {
		if activeSLORule(resource) {
			count++
		}
	}
	return count
}

func activeSLORule(resource model.Resource) bool {
	if resource.Status != model.ResourceStatusActive || resource.Metadata[model.MetadataSLORule] != "true" {
		return false
	}
	if resource.Type == model.ResourceTypeAlertRule {
		return !isDisabledAlert(resource)
	}
	return resource.Type == model.ResourceTypeRecordingRule
}
