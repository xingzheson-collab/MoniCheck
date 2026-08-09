package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const OTelExporterQueueSaturatedAnalyzerID = "builtin.otelcol_exporter_queue_saturated"

type OTelExporterQueueSaturatedAnalyzer struct{}

func NewOTelExporterQueueSaturatedAnalyzer() *OTelExporterQueueSaturatedAnalyzer {
	return &OTelExporterQueueSaturatedAnalyzer{}
}

func (a *OTelExporterQueueSaturatedAnalyzer) ID() string {
	return OTelExporterQueueSaturatedAnalyzerID
}

func (a *OTelExporterQueueSaturatedAnalyzer) Name() string {
	return "OpenTelemetry Collector Exporter Queue Saturated"
}

func (a *OTelExporterQueueSaturatedAnalyzer) Version() string { return "0.1.0" }

func (a *OTelExporterQueueSaturatedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelExporterQueueSaturatedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if observed == 0 || saturated == 0 {
			continue
		}
		maxUtilization := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterQueueMaxUtilizationPercent])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "OTelExporterQueueSaturated",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Status:   model.FindingStatusOpen,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{fmt.Sprintf(
				"OpenTelemetry Collector has observed %d saturated exporter sending queue(s) across %d evaluable queue(s); maximum utilization is %s%%",
				saturated,
				observed,
				formatOTelColRuntimeEvidenceValue(maxUtilization),
			)},
			Recommendation: "检查 queue_size 与 queue_capacity 的当前值和持续时间；结合 enqueue_failed、send_failed、后端延迟与 Collector 内存，增加消费者或受预算约束的队列容量，必要时水平扩容，并验证积压能够回落。",
			Metadata: map[string]string{
				"analyzer_id":             a.ID(),
				"observed_queue_count":    strconv.Itoa(observed),
				"saturated_queue_count":   strconv.Itoa(saturated),
				"max_utilization_percent": formatOTelColRuntimeEvidenceValue(maxUtilization),
			},
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func positiveOTelColRuntimeInteger(value string) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}
