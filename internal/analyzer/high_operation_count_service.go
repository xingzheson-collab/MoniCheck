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
	HighOperationCountServiceAnalyzerID               = "builtin.high_operation_count_service"
	defaultTraceOperationCountServiceThreshold        = 50
	defaultTraceOperationCountServiceOperationSamples = 8
)

type HighOperationCountServiceAnalyzer struct{}

func NewHighOperationCountServiceAnalyzer() *HighOperationCountServiceAnalyzer {
	return &HighOperationCountServiceAnalyzer{}
}

func (a *HighOperationCountServiceAnalyzer) ID() string {
	return HighOperationCountServiceAnalyzerID
}

func (a *HighOperationCountServiceAnalyzer) Name() string {
	return "High Trace Operation Count Service"
}

func (a *HighOperationCountServiceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighOperationCountServiceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService, model.ResourceTypeTraceOperation}
}

func (a *HighOperationCountServiceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	threshold := intConfig(analysis.Config, "trace_operation_count_threshold", defaultTraceOperationCountServiceThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, service := range services {
		if service.Status != model.ResourceStatusActive {
			continue
		}
		operations := traceOperationsForService(service.ID, analysis)
		operationCount := len(operations)
		if service.Metadata[model.MetadataOperationDiscoveryAvailable] == "true" {
			discoveredCount, parseErr := strconv.Atoi(service.Metadata[model.MetadataOperationCount])
			if parseErr == nil && discoveredCount > operationCount {
				operationCount = discoveredCount
			}
		}
		if operationCount <= threshold {
			continue
		}
		operationNames := sampledConsumerNames(operations, defaultTraceOperationCountServiceOperationSamples)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), service.ID),
			Type:     "HighOperationCountService",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   service.ID,
				Type: service.Type,
				Name: service.Name,
			},
			Evidence: []string{
				fmt.Sprintf("service %q has %d trace operations, threshold is %d", service.Name, operationCount, threshold),
				fmt.Sprintf("sample operations: %s", strings.Join(operationNames, ", ")),
			},
			Recommendation: "检查 Jaeger span operation 命名是否包含动态 ID、URL 原始路径或请求载荷；优先使用低基数路由模板和稳定业务动作名。",
			Metadata: map[string]string{
				"analyzer_id":       a.ID(),
				"operation_count":   strconv.Itoa(operationCount),
				"threshold":         strconv.Itoa(threshold),
				"operations":        strings.Join(operationNames, ","),
				"catalog_truncated": service.Metadata[model.MetadataOperationDiscoveryTruncated],
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func traceOperationsForService(serviceID string, analysis Context) []model.Resource {
	seen := make(map[string]bool)
	operations := make([]model.Resource, 0)
	for _, relationship := range analysis.Graph.Incoming(serviceID) {
		if relationship.Type != model.RelationshipBelongsTo || seen[relationship.FromID] {
			continue
		}
		resource, ok := analysis.Graph.Resource(relationship.FromID)
		if !ok || resource.Status != model.ResourceStatusActive || resource.Type != model.ResourceTypeTraceOperation {
			continue
		}
		seen[resource.ID] = true
		operations = append(operations, resource)
	}
	sortResourcesByTypeAndName(operations)
	return operations
}
