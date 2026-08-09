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

const (
	HighImpactServiceAnalyzerID               = "builtin.high_impact_service"
	defaultHighImpactServiceResourceThreshold = 10
)

type HighImpactServiceAnalyzer struct{}

func NewHighImpactServiceAnalyzer() *HighImpactServiceAnalyzer {
	return &HighImpactServiceAnalyzer{}
}

func (a *HighImpactServiceAnalyzer) ID() string {
	return HighImpactServiceAnalyzerID
}

func (a *HighImpactServiceAnalyzer) Name() string {
	return "High Impact Service"
}

func (a *HighImpactServiceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighImpactServiceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService}
}

func (a *HighImpactServiceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	threshold := intConfig(analysis.Config, "high_impact_service_resource_threshold", defaultHighImpactServiceResourceThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, service := range services {
		if service.Status != model.ResourceStatusActive {
			continue
		}
		members := serviceMembers(service.ID, analysis)
		if len(members) <= threshold {
			continue
		}

		memberNames := sampledConsumerNames(members, defaultHighImpactMetricConsumerNameSample)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), service.ID),
			Type:     "HighImpactService",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   service.ID,
				Type: service.Type,
				Name: service.Name,
			},
			Evidence: []string{
				fmt.Sprintf("service %q has %d attributed or derived-impact monitoring resources, threshold is %d", service.Name, len(members), threshold),
				fmt.Sprintf("sample resources: %s", strings.Join(memberNames, ", ")),
			},
			Recommendation: "将该业务服务纳入重点治理范围；监控资源、Recording Rule、告警规则、Dashboard 或采集配置变更前先评估服务级影响面和 owner 协作。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"resource_count": strconv.Itoa(len(members)),
				"threshold":      strconv.Itoa(threshold),
				"resources":      strings.Join(memberNames, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func serviceMembers(serviceID string, analysis Context) []model.Resource {
	seen := make(map[string]bool)
	members := make([]model.Resource, 0)
	queue := make([]string, 0)
	for _, relationship := range analysis.Graph.Incoming(serviceID) {
		if relationship.Type != model.RelationshipBelongsTo || seen[relationship.FromID] {
			continue
		}
		member, ok := analysis.Graph.Resource(relationship.FromID)
		if !ok || member.Status != model.ResourceStatusActive {
			continue
		}
		if !isServiceMemberResource(member.Type) {
			continue
		}
		seen[member.ID] = true
		members = append(members, member)
		queue = append(queue, member.ID)
	}
	for len(queue) > 0 {
		resourceID := queue[0]
		queue = queue[1:]
		relationships := append([]model.Relationship{}, analysis.Graph.Outgoing(resourceID)...)
		relationships = append(relationships, analysis.Graph.Incoming(resourceID)...)
		for _, relationship := range relationships {
			var nextID string
			switch {
			case relationship.FromID == resourceID && relationship.Type == model.RelationshipProduces:
				nextID = relationship.ToID
			case relationship.ToID == resourceID && (relationship.Type == model.RelationshipUses || relationship.Type == model.RelationshipProduces):
				nextID = relationship.FromID
			default:
				continue
			}
			if seen[nextID] {
				continue
			}
			member, ok := analysis.Graph.Resource(nextID)
			if !ok || member.Status != model.ResourceStatusActive {
				continue
			}
			if !isServiceMemberResource(member.Type) {
				continue
			}
			seen[member.ID] = true
			members = append(members, member)
			queue = append(queue, member.ID)
		}
	}
	sortResourcesByTypeAndName(members)
	return members
}

func isServiceMemberResource(resourceType model.ResourceType) bool {
	switch resourceType {
	case model.ResourceTypeMetric,
		model.ResourceTypeDashboard,
		model.ResourceTypeFolder,
		model.ResourceTypePanel,
		model.ResourceTypeDatasource,
		model.ResourceTypeAlert,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeTarget,
		model.ResourceTypeExporter,
		model.ResourceTypeJob,
		model.ResourceTypeInstance,
		model.ResourceTypeTraceOperation,
		model.ResourceTypeLogStream,
		model.ResourceTypeTraceService,
		model.ResourceTypeProfileService,
		model.ResourceTypeTable:
		return true
	default:
		return false
	}
}
