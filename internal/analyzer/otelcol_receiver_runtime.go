package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const OTelReceiverRefusedTelemetryAnalyzerID = "builtin.otelcol_receiver_refused_telemetry"

type OTelReceiverRefusedTelemetryAnalyzer struct{}

func NewOTelReceiverRefusedTelemetryAnalyzer() *OTelReceiverRefusedTelemetryAnalyzer {
	return &OTelReceiverRefusedTelemetryAnalyzer{}
}

func (a *OTelReceiverRefusedTelemetryAnalyzer) ID() string {
	return OTelReceiverRefusedTelemetryAnalyzerID
}

func (a *OTelReceiverRefusedTelemetryAnalyzer) Name() string {
	return "OpenTelemetry Collector Receiver Refused Telemetry"
}

func (a *OTelReceiverRefusedTelemetryAnalyzer) Version() string { return "0.1.0" }

func (a *OTelReceiverRefusedTelemetryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelReceiverRefusedTelemetryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		logRecords := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelReceiverRefusedLogRecords])
		metricPoints := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelReceiverRefusedMetricPoints])
		spans := positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelReceiverRefusedSpans])
		counterEvidence := otelColRuntimeCounterEvidence(resource.Metadata, model.MetadataOTelReceiverRefusedDelta)
		if !counterEvidence.shouldReport(logRecords + metricPoints + spans) {
			continue
		}
		if otelColReceiverHighRefusalRatio(resource.Metadata) {
			continue
		}
		evidence := ""
		if counterEvidence.DeltaAvailable {
			evidence = fmt.Sprintf(
				"OpenTelemetry Collector receiver refusal counters increased by %s telemetry item(s) during the latest %s-second successful-scrape interval; cumulative totals are %s log record(s), %s metric point(s), and %s span(s)",
				formatOTelColRuntimeEvidenceValue(counterEvidence.Delta),
				formatOTelColRuntimeEvidenceValue(counterEvidence.IntervalSeconds),
				formatOTelColRuntimeEvidenceValue(logRecords),
				formatOTelColRuntimeEvidenceValue(metricPoints),
				formatOTelColRuntimeEvidenceValue(spans),
			)
		} else {
			evidence = fmt.Sprintf(
				"OpenTelemetry Collector receivers have observed %s refused log record(s), %s metric point(s), and %s span(s) since runtime counters were reset",
				formatOTelColRuntimeEvidenceValue(logRecords),
				formatOTelColRuntimeEvidenceValue(metricPoints),
				formatOTelColRuntimeEvidenceValue(spans),
			)
		}
		findingMetadata := map[string]string{
			"analyzer_id":   a.ID(),
			"log_records":   formatOTelColRuntimeEvidenceValue(logRecords),
			"metric_points": formatOTelColRuntimeEvidenceValue(metricPoints),
			"spans":         formatOTelColRuntimeEvidenceValue(spans),
		}
		addOTelColRuntimeCounterEvidence(findingMetadata, counterEvidence)
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "OTelReceiverRefusedTelemetry",
			Severity:       model.SeverityWarning,
			Category:       model.FindingCategoryReliability,
			Status:         model.FindingStatusOpen,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{evidence},
			Recommendation: "检查 receiver_refused 指标的当前增长率、Collector 内存与 processor/exporter 背压；确认客户端收到错误后会重试且重试窗口足够，并通过 accepted 指标和客户端侧发送结果验证数据已恢复。",
			Metadata:       findingMetadata,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
	}
	return findings, nil
}
