package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	OTelReceiverHighRefusalRatioAnalyzerID       = "builtin.otelcol_receiver_high_refusal_ratio"
	OTelReceiverHighRefusalRatioThresholdPercent = 10.0
)

type OTelReceiverHighRefusalRatioAnalyzer struct{}

func NewOTelReceiverHighRefusalRatioAnalyzer() *OTelReceiverHighRefusalRatioAnalyzer {
	return &OTelReceiverHighRefusalRatioAnalyzer{}
}

func (a *OTelReceiverHighRefusalRatioAnalyzer) ID() string {
	return OTelReceiverHighRefusalRatioAnalyzerID
}

func (a *OTelReceiverHighRefusalRatioAnalyzer) Name() string {
	return "OpenTelemetry Collector Receiver High Refusal Ratio"
}

func (a *OTelReceiverHighRefusalRatioAnalyzer) Version() string { return "0.1.0" }

func (a *OTelReceiverHighRefusalRatioAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelReceiverHighRefusalRatioAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
			!otelColReceiverHighRefusalRatio(resource.Metadata) {
			continue
		}
		refused := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelReceiverRefusedDelta])
		accepted := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelReceiverAcceptedTelemetryDelta])
		ratio := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelReceiverRefusalRatioPercent])
		interval := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "OTelReceiverHighRefusalRatio",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryReliability,
			Status:   model.FindingStatusOpen,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{fmt.Sprintf(
				"OpenTelemetry Collector receivers refused %s telemetry item(s) and accepted %s during the latest %s-second successful-scrape interval, a %s%% refusal ratio at or above the %s%% critical threshold",
				formatOTelColRuntimeEvidenceValue(refused),
				formatOTelColRuntimeEvidenceValue(accepted),
				formatOTelColRuntimeEvidenceValue(interval),
				formatOTelColRuntimeEvidenceValue(ratio),
				formatOTelColRuntimeEvidenceValue(OTelReceiverHighRefusalRatioThresholdPercent),
			)},
			Recommendation: "立即检查 Collector 内存、processor/exporter 背压、接收并发与客户端错误；恢复下游吞吐或水平扩容，并确认客户端重试窗口足够，拒绝率回落且 accepted 增量恢复。",
			Metadata: map[string]string{
				"analyzer_id":              a.ID(),
				"refused_delta":            formatOTelColRuntimeEvidenceValue(refused),
				"accepted_delta":           formatOTelColRuntimeEvidenceValue(accepted),
				"refusal_ratio_percent":    formatOTelColRuntimeEvidenceValue(ratio),
				"threshold_percent":        formatOTelColRuntimeEvidenceValue(OTelReceiverHighRefusalRatioThresholdPercent),
				"counter_interval_seconds": formatOTelColRuntimeEvidenceValue(interval),
			},
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func otelColReceiverHighRefusalRatio(metadata map[string]string) bool {
	if metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] != "true" ||
		metadata[model.MetadataOTelReceiverRefusalRatioEvaluable] != "true" {
		return false
	}
	refused := positiveOTelColRuntimeMetric(metadata[model.MetadataOTelReceiverRefusedDelta])
	ratio := positiveOTelColRuntimeMetric(metadata[model.MetadataOTelReceiverRefusalRatioPercent])
	return refused > 0 && ratio >= OTelReceiverHighRefusalRatioThresholdPercent
}
