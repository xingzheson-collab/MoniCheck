package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	OTelExporterQueueNearSaturationAnalyzerID = "builtin.otelcol_exporter_queue_near_saturation"
	otelExporterQueueNearSaturationPercent    = 80.0
)

type OTelExporterQueueNearSaturationAnalyzer struct{}

func NewOTelExporterQueueNearSaturationAnalyzer() *OTelExporterQueueNearSaturationAnalyzer {
	return &OTelExporterQueueNearSaturationAnalyzer{}
}

func (a *OTelExporterQueueNearSaturationAnalyzer) ID() string {
	return OTelExporterQueueNearSaturationAnalyzerID
}

func (a *OTelExporterQueueNearSaturationAnalyzer) Name() string {
	return "OpenTelemetry Collector Exporter Queue Near Saturation"
}

func (a *OTelExporterQueueNearSaturationAnalyzer) Version() string { return "0.1.0" }

func (a *OTelExporterQueueNearSaturationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelExporterQueueNearSaturationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "otelcol" ||
			resource.Metadata[model.MetadataOTelRuntimeMetricsAvailable] != "true" {
			continue
		}
		observed := positiveOTelColRuntimeInteger(resource.Metadata[model.MetadataOTelExporterQueueObservedCount])
		saturated := positiveOTelColRuntimeInteger(resource.Metadata[model.MetadataOTelExporterQueueSaturatedCount])
		maxUtilization := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterQueueMaxUtilizationPercent])
		if observed == 0 ||
			saturated > 0 ||
			maxUtilization < otelExporterQueueNearSaturationPercent ||
			maxUtilization >= 100 {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "OTelExporterQueueNearSaturation",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Status:   model.FindingStatusOpen,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{fmt.Sprintf(
				"OpenTelemetry Collector exporter sending queues have reached %s%% maximum utilization across %d evaluable queue(s), below full saturation",
				formatOTelColRuntimeEvidenceValue(maxUtilization),
				observed,
			)},
			Recommendation: "检查 queue_size 与 queue_capacity 是否持续接近上限，并结合 enqueue_failed、send_failed、后端延迟和 Collector 内存确认原因；优先恢复后端吞吐，必要时增加消费者、受预算约束的队列容量或水平扩容。",
			Metadata: map[string]string{
				"analyzer_id":             a.ID(),
				"observed_queue_count":    strconv.Itoa(observed),
				"max_utilization_percent": formatOTelColRuntimeEvidenceValue(maxUtilization),
				"threshold_percent":       formatOTelColRuntimeEvidenceValue(otelExporterQueueNearSaturationPercent),
			},
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
