package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UnusedOTelComponentAnalyzerID = "builtin.unused_otel_component"

type UnusedOTelComponentAnalyzer struct{}

func NewUnusedOTelComponentAnalyzer() *UnusedOTelComponentAnalyzer {
	return &UnusedOTelComponentAnalyzer{}
}

func (a *UnusedOTelComponentAnalyzer) ID() string {
	return UnusedOTelComponentAnalyzerID
}

func (a *UnusedOTelComponentAnalyzer) Name() string {
	return "Unused OpenTelemetry Collector Component"
}

func (a *UnusedOTelComponentAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnusedOTelComponentAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeReceiver, model.ResourceTypeProcessor, model.ResourceTypeExporter, model.ResourceTypeExtension, model.ResourceTypeTelemetryConnector}
}

func (a *UnusedOTelComponentAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	componentUses := map[string]bool{}
	if analysis.Graph != nil {
		for _, resource := range resources {
			if !isActiveOTelUsageOwner(resource) {
				continue
			}
			for _, relationship := range analysis.Graph.Outgoing(resource.ID) {
				if relationship.Type == model.RelationshipUses {
					componentUses[relationship.ToID] = true
				}
			}
		}
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if !isActiveOTelComponent(resource) {
			continue
		}
		if componentUses[resource.ID] {
			continue
		}
		kind := strings.TrimSpace(resource.Metadata[model.MetadataComponentKind])
		if kind == "" {
			kind = strings.ToLower(string(resource.Type))
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "UnusedOTelComponent",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("OpenTelemetry Collector %s %q is not enabled or referenced by the active service configuration", kind, resource.Name),
			},
			Recommendation: "删除未使用的 Collector 组件，或将 receiver/processor/exporter 接入明确的 pipeline、将 extension 加入 service.extensions，减少配置漂移和误解。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"component_kind": kind,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Resource.Type != findings[j].Resource.Type {
			return findings[i].Resource.Type < findings[j].Resource.Type
		}
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func isOTelComponentResource(resourceType model.ResourceType) bool {
	switch resourceType {
	case model.ResourceTypeReceiver, model.ResourceTypeProcessor, model.ResourceTypeExporter, model.ResourceTypeExtension, model.ResourceTypeTelemetryConnector:
		return true
	default:
		return false
	}
}

func isActiveOTelPipeline(resource model.Resource) bool {
	return resource.Type == model.ResourceTypePipeline &&
		resource.Source.System == "otelcol" &&
		resource.Status == model.ResourceStatusActive
}

func isActiveOTelUsageOwner(resource model.Resource) bool {
	return isActiveOTelPipeline(resource) ||
		(resource.Type == model.ResourceTypeInstance &&
			resource.Source.System == "otelcol" &&
			resource.Status == model.ResourceStatusActive &&
			resource.Metadata[model.MetadataOTelCollectorConfigInstance] == "true")
}

func isActiveOTelComponent(resource model.Resource) bool {
	return resource.Source.System == "otelcol" &&
		resource.Status == model.ResourceStatusActive &&
		isOTelComponentResource(resource.Type)
}
