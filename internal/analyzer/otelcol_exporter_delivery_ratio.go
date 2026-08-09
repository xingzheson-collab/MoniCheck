package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	OTelExporterHighSendFailureRatioAnalyzerID       = "builtin.otelcol_exporter_high_send_failure_ratio"
	OTelExporterHighSendFailureRatioThresholdPercent = 10.0
)

type OTelExporterHighSendFailureRatioAnalyzer struct{}

func NewOTelExporterHighSendFailureRatioAnalyzer() *OTelExporterHighSendFailureRatioAnalyzer {
	return &OTelExporterHighSendFailureRatioAnalyzer{}
}

func (a *OTelExporterHighSendFailureRatioAnalyzer) ID() string {
	return OTelExporterHighSendFailureRatioAnalyzerID
}

func (a *OTelExporterHighSendFailureRatioAnalyzer) Name() string {
	return "OpenTelemetry Collector Exporter High Send Failure Ratio"
}

func (a *OTelExporterHighSendFailureRatioAnalyzer) Version() string { return "0.1.0" }

func (a *OTelExporterHighSendFailureRatioAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelExporterHighSendFailureRatioAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
			!otelColExporterHighSendFailureRatio(resource.Metadata) {
			continue
		}
		failed := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterSendFailureDelta])
		sent := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterSentTelemetryDelta])
		ratio := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterSendFailureRatioPercent])
		interval := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "OTelExporterHighSendFailureRatio",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryReliability,
			Status:   model.FindingStatusOpen,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{fmt.Sprintf(
				"OpenTelemetry Collector exporters failed to send %s telemetry item(s) and successfully sent %s during the latest %s-second successful-scrape interval, a %s%% failure ratio at or above the %s%% critical threshold",
				formatOTelColRuntimeEvidenceValue(failed),
				formatOTelColRuntimeEvidenceValue(sent),
				formatOTelColRuntimeEvidenceValue(interval),
				formatOTelColRuntimeEvidenceValue(ratio),
				formatOTelColRuntimeEvidenceValue(OTelExporterHighSendFailureRatioThresholdPercent),
			)},
			Recommendation: "立即检查 Collector 日志、后端可用性、网络、认证和限流；确认 retry_on_failure 与 sending_queue 能覆盖故障窗口，优先恢复后端吞吐或水平扩容，并验证失败率回落且积压被成功发送。",
			Metadata: map[string]string{
				"analyzer_id":              a.ID(),
				"failed_delta":             formatOTelColRuntimeEvidenceValue(failed),
				"sent_delta":               formatOTelColRuntimeEvidenceValue(sent),
				"failure_ratio_percent":    formatOTelColRuntimeEvidenceValue(ratio),
				"threshold_percent":        formatOTelColRuntimeEvidenceValue(OTelExporterHighSendFailureRatioThresholdPercent),
				"counter_interval_seconds": formatOTelColRuntimeEvidenceValue(interval),
			},
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func otelColExporterHighSendFailureRatio(metadata map[string]string) bool {
	if metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] != "true" ||
		metadata[model.MetadataOTelExporterSendFailureRatioEvaluable] != "true" {
		return false
	}
	failed := positiveOTelColRuntimeMetric(metadata[model.MetadataOTelExporterSendFailureDelta])
	ratio := positiveOTelColRuntimeMetric(metadata[model.MetadataOTelExporterSendFailureRatioPercent])
	return failed > 0 && ratio >= OTelExporterHighSendFailureRatioThresholdPercent
}
