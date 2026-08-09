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

const DebugOTelExporterAnalyzerID = "builtin.debug_otel_exporter"

type DebugOTelExporterAnalyzer struct{}

func NewDebugOTelExporterAnalyzer() *DebugOTelExporterAnalyzer {
	return &DebugOTelExporterAnalyzer{}
}

func (a *DebugOTelExporterAnalyzer) ID() string {
	return DebugOTelExporterAnalyzerID
}

func (a *DebugOTelExporterAnalyzer) Name() string {
	return "Debug OpenTelemetry Collector Exporter"
}

func (a *DebugOTelExporterAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DebugOTelExporterAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeExporter}
}

func (a *DebugOTelExporterAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	exporters, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeExporter})
	if err != nil {
		return nil, err
	}

	usedByPipeline := map[string]bool{}
	if analysis.Graph != nil {
		resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
		if err != nil {
			return nil, err
		}
		for _, resource := range resources {
			if !isActiveOTelPipeline(resource) {
				continue
			}
			for _, relationship := range analysis.Graph.Outgoing(resource.ID) {
				if relationship.Type == model.RelationshipUses {
					usedByPipeline[relationship.ToID] = true
				}
			}
		}
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, exporter := range exporters {
		if !isActiveOTelComponent(exporter) || !usedByPipeline[exporter.ID] {
			continue
		}
		exporterType := otelComponentType(exporter)
		if exporterType != "debug" && exporterType != "logging" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), exporter.ID, exporterType),
			Type:     "DebugOTelExporter",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   exporter.ID,
				Type: exporter.Type,
				Name: exporter.Name,
			},
			Evidence: []string{
				fmt.Sprintf("OpenTelemetry Collector exporter %q uses %q and is referenced by a service pipeline", exporter.Name, exporterType),
			},
			Recommendation: "生产 Collector pipeline 不建议使用 debug/logging exporter 作为常规输出；请改用 OTLP、Prometheus remote write、Loki、Kafka 等目标后端，或仅在临时排障时启用。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"component_type": exporterType,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func otelComponentType(resource model.Resource) string {
	componentType := strings.TrimSpace(resource.Metadata[model.MetadataComponentType])
	if componentType == "" {
		componentType = strings.TrimSpace(resource.Name)
	}
	if index := strings.Index(componentType, "/"); index >= 0 {
		componentType = componentType[:index]
	}
	return strings.ToLower(strings.TrimSpace(componentType))
}
