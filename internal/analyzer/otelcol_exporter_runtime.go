package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	OTelExporterEnqueueFailuresAnalyzerID = "builtin.otelcol_exporter_enqueue_failures"
	OTelExporterSendFailuresAnalyzerID    = "builtin.otelcol_exporter_send_failures"
)

type OTelExporterRuntimeAnalyzer struct {
	id   string
	name string
}

func NewOTelExporterEnqueueFailuresAnalyzer() *OTelExporterRuntimeAnalyzer {
	return &OTelExporterRuntimeAnalyzer{
		id:   OTelExporterEnqueueFailuresAnalyzerID,
		name: "OpenTelemetry Collector Exporter Enqueue Failures",
	}
}

func NewOTelExporterSendFailuresAnalyzer() *OTelExporterRuntimeAnalyzer {
	return &OTelExporterRuntimeAnalyzer{
		id:   OTelExporterSendFailuresAnalyzerID,
		name: "OpenTelemetry Collector Exporter Send Failures",
	}
}

func (a *OTelExporterRuntimeAnalyzer) ID() string      { return a.id }
func (a *OTelExporterRuntimeAnalyzer) Name() string    { return a.name }
func (a *OTelExporterRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *OTelExporterRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OTelExporterRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (a *OTelExporterRuntimeAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	var logRecords, metricPoints, spans float64
	var findingType, action, recommendation string
	var deltaKey string
	severity := model.SeverityWarning

	switch a.id {
	case OTelExporterEnqueueFailuresAnalyzerID:
		logRecords = positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterEnqueueFailedLogRecords])
		metricPoints = positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterEnqueueFailedMetricPoints])
		spans = positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterEnqueueFailedSpans])
		findingType = "OTelExporterEnqueueFailures"
		deltaKey = model.MetadataOTelExporterEnqueueFailureDelta
		action = "failed to enqueue"
		severity = model.SeverityCritical
		recommendation = "检查 exporter sending queue 的当前利用率和 enqueue_failed 指标增长；确认后端延迟、消费者数量、队列容量与 Collector 内存预算，必要时水平扩容，并验证上游重试能覆盖已拒绝的数据。"
	case OTelExporterSendFailuresAnalyzerID:
		logRecords = positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterSendFailedLogRecords])
		metricPoints = positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterSendFailedMetricPoints])
		spans = positiveOTelColRuntimeMetric(resource.Metadata[model.MetadataOTelExporterSendFailedSpans])
		findingType = "OTelExporterSendFailures"
		deltaKey = model.MetadataOTelExporterSendFailureDelta
		action = "failed to send"
		recommendation = "检查 send_failed 指标的当前增长率、Collector 日志、后端可用性、网络与认证；确认 retry_on_failure 和 sending_queue 能覆盖故障窗口，并以 sent 指标验证积压恢复而非持续失败。"
	default:
		return model.Finding{}, false
	}
	counterEvidence := otelColRuntimeCounterEvidence(resource.Metadata, deltaKey)
	if !counterEvidence.shouldReport(logRecords + metricPoints + spans) {
		return model.Finding{}, false
	}
	if a.id == OTelExporterSendFailuresAnalyzerID && otelColExporterHighSendFailureRatio(resource.Metadata) {
		return model.Finding{}, false
	}
	evidence := ""
	if counterEvidence.DeltaAvailable {
		evidence = fmt.Sprintf(
			"OpenTelemetry Collector exporter %s counters increased by %s telemetry item(s) during the latest %s-second successful-scrape interval; cumulative totals are %s log record(s), %s metric point(s), and %s span(s)",
			action,
			formatOTelColRuntimeEvidenceValue(counterEvidence.Delta),
			formatOTelColRuntimeEvidenceValue(counterEvidence.IntervalSeconds),
			formatOTelColRuntimeEvidenceValue(logRecords),
			formatOTelColRuntimeEvidenceValue(metricPoints),
			formatOTelColRuntimeEvidenceValue(spans),
		)
	} else {
		evidence = fmt.Sprintf(
			"OpenTelemetry Collector exporters have observed %s %s log record(s), %s metric point(s), and %s span(s) since runtime counters were reset",
			formatOTelColRuntimeEvidenceValue(logRecords),
			action,
			formatOTelColRuntimeEvidenceValue(metricPoints),
			formatOTelColRuntimeEvidenceValue(spans),
		)
	}
	findingMetadata := map[string]string{
		"analyzer_id":   a.id,
		"log_records":   formatOTelColRuntimeEvidenceValue(logRecords),
		"metric_points": formatOTelColRuntimeEvidenceValue(metricPoints),
		"spans":         formatOTelColRuntimeEvidenceValue(spans),
	}
	addOTelColRuntimeCounterEvidence(findingMetadata, counterEvidence)

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       severity,
		Category:       model.FindingCategoryReliability,
		Status:         model.FindingStatusOpen,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       findingMetadata,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}
