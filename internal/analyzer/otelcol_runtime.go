package analyzer

import (
	"context"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const OTelCollectorRuntimeUnhealthyAnalyzerID = "builtin.otelcol_runtime_unhealthy"

type OTelCollectorRuntimeUnhealthyAnalyzer struct{}

func NewOTelCollectorRuntimeUnhealthyAnalyzer() *OTelCollectorRuntimeUnhealthyAnalyzer {
	return &OTelCollectorRuntimeUnhealthyAnalyzer{}
}

func (a *OTelCollectorRuntimeUnhealthyAnalyzer) ID() string {
	return OTelCollectorRuntimeUnhealthyAnalyzerID
}

func (a *OTelCollectorRuntimeUnhealthyAnalyzer) Name() string {
	return "OpenTelemetry Collector Runtime Unhealthy"
}

func (a *OTelCollectorRuntimeUnhealthyAnalyzer) Version() string {
	return "1.0.0"
}

func (a *OTelCollectorRuntimeUnhealthyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelCollectorRuntimeUnhealthyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "otelcol" ||
			resource.Metadata[model.MetadataOTelCollectorRuntime] != "true" ||
			resource.Metadata[model.MetadataOTelRuntimeHealthAvailable] != "true" ||
			resource.Metadata[model.MetadataOTelRuntimeHealthy] != "false" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "OTelCollectorRuntimeUnhealthy",
			Severity:       model.SeverityCritical,
			Category:       model.FindingCategoryReliability,
			Status:         model.FindingStatusOpen,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{"The configured OpenTelemetry Collector health endpoint returned HTTP 503 and explicitly reported the runtime as unhealthy"},
			Recommendation: "Inspect Collector startup, pipeline, extension, exporter, and dependency errors; restore the configured health endpoint to a successful response and verify telemetry delivery.",
			Metadata: map[string]string{
				"analyzer_id":   a.ID(),
				"healthy":       "false",
				"health_source": resource.Metadata[model.MetadataOTelRuntimeHealthSource],
			},
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
