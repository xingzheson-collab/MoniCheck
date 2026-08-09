package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const OTelCollectorProcessTelemetryIncompleteAnalyzerID = "builtin.otelcol_process_telemetry_incomplete"

const otelcolExpectedProcessTelemetryMetricCount = 6

type OTelCollectorProcessTelemetryIncompleteAnalyzer struct{}

func NewOTelCollectorProcessTelemetryIncompleteAnalyzer() *OTelCollectorProcessTelemetryIncompleteAnalyzer {
	return &OTelCollectorProcessTelemetryIncompleteAnalyzer{}
}

func (a *OTelCollectorProcessTelemetryIncompleteAnalyzer) ID() string {
	return OTelCollectorProcessTelemetryIncompleteAnalyzerID
}

func (a *OTelCollectorProcessTelemetryIncompleteAnalyzer) Name() string {
	return "OpenTelemetry Collector Process Telemetry Incomplete"
}

func (a *OTelCollectorProcessTelemetryIncompleteAnalyzer) Version() string { return "0.1.0" }

func (a *OTelCollectorProcessTelemetryIncompleteAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelCollectorProcessTelemetryIncompleteAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "otelcol" ||
			resource.Metadata[model.MetadataOTelRuntimeMetricsAvailable] != "true" ||
			resource.Metadata[model.MetadataOTelProcessTelemetryObserved] != "true" {
			continue
		}
		missingCount, err := strconv.Atoi(resource.Metadata[model.MetadataOTelProcessTelemetryMissingCount])
		if err != nil || missingCount <= 0 || missingCount >= otelcolExpectedProcessTelemetryMetricCount {
			continue
		}
		availableCount := otelcolExpectedProcessTelemetryMetricCount - missingCount
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "OTelCollectorProcessTelemetryIncomplete",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryConfiguration,
			Status:   model.FindingStatusOpen,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{fmt.Sprintf(
				"The OpenTelemetry Collector metrics endpoint exposes %d of %d canonical basic process metric families; %d family or families are missing",
				availableCount,
				otelcolExpectedProcessTelemetryMetricCount,
				missingCount,
			)},
			Recommendation: "恢复 Collector 的 canonical basic process metrics（uptime、CPU、RSS、heap allocation、total allocation 和 runtime system memory），或修正 internal telemetry views/Prometheus exporter 命名；随后重新运行治理以确认进程健康与重启证据完整。",
			Metadata: map[string]string{
				"analyzer_id":            a.ID(),
				"available_metric_count": strconv.Itoa(availableCount),
				"expected_metric_count":  strconv.Itoa(otelcolExpectedProcessTelemetryMetricCount),
				"missing_metric_count":   strconv.Itoa(missingCount),
			},
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
