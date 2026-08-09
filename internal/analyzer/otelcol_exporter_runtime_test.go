package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelExporterRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	enqueue := otelcolExporterRuntimeResource("enqueue", "true", "3", "4", "5", "0", "0", "0")
	send := otelcolExporterRuntimeResource("send", "true", "0", "0", "0", "6", "7", "8")
	healthy := otelcolExporterRuntimeResource("healthy", "true", "0", "0", "0", "0", "0", "0")
	unavailable := otelcolExporterRuntimeResource("unavailable", "false", "3", "4", "5", "6", "7", "8")
	wrongSource := otelcolExporterRuntimeResource("wrong-source", "true", "3", "4", "5", "6", "7", "8")
	wrongSource.Source.System = "plugin"
	for _, resource := range []model.Resource{enqueue, send, healthy, unavailable, wrongSource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	tests := []struct {
		analyzer    Analyzer
		resourceID  string
		findingType string
		severity    model.Severity
		evidence    string
	}{
		{NewOTelExporterEnqueueFailuresAnalyzer(), enqueue.ID, "OTelExporterEnqueueFailures", model.SeverityCritical, "3 failed to enqueue log record(s), 4 metric point(s), and 5 span(s)"},
		{NewOTelExporterSendFailuresAnalyzer(), send.ID, "OTelExporterSendFailures", model.SeverityWarning, "6 failed to send log record(s), 7 metric point(s), and 8 span(s)"},
	}
	for _, test := range tests {
		t.Run(test.analyzer.ID(), func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if len(findings) != 1 ||
				findings[0].Resource.ID != test.resourceID ||
				findings[0].Type != test.findingType ||
				findings[0].Severity != test.severity ||
				findings[0].Category != model.FindingCategoryReliability ||
				!strings.Contains(findings[0].Evidence[0], test.evidence) ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
				t.Fatalf("unexpected findings: %#v", findings)
			}
			encoded, err := json.Marshal(findings[0])
			if err != nil {
				t.Fatalf("marshal finding: %v", err)
			}
			for _, privateValue := range []string{"private-exporter", "private-instance", "private-label"} {
				if strings.Contains(string(encoded), privateValue) {
					t.Fatalf("finding leaked %q: %s", privateValue, encoded)
				}
			}
		})
	}
}

func TestOTelExporterRuntimeAnalyzersPreferCounterDeltas(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	stable := otelcolExporterRuntimeResource("stable-delta", "true", "3", "4", "5", "6", "7", "8")
	growing := otelcolExporterRuntimeResource("growing-delta", "true", "4", "4", "5", "6", "8", "8")
	for _, resource := range []*model.Resource{&stable, &growing} {
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] = "true"
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds] = "60"
	}
	stable.Metadata[model.MetadataOTelExporterEnqueueFailureDelta] = "0"
	stable.Metadata[model.MetadataOTelExporterSendFailureDelta] = "0"
	growing.Metadata[model.MetadataOTelExporterEnqueueFailureDelta] = "1"
	growing.Metadata[model.MetadataOTelExporterSendFailureDelta] = "1"
	for _, resource := range []model.Resource{stable, growing} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, item := range []Analyzer{NewOTelExporterEnqueueFailuresAnalyzer(), NewOTelExporterSendFailuresAnalyzer()} {
		findings, err := item.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != growing.ID ||
			findings[0].Metadata["counter_evidence"] != "delta" ||
			findings[0].Metadata["counter_delta"] != "1" {
			t.Fatalf("unexpected delta finding for %s: findings=%#v err=%v", item.ID(), findings, err)
		}
	}
}

func TestOTelExporterSendFailureAnalyzersAreMutuallyExclusiveAtRatioThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	below := otelcolExporterRuntimeResource("below-ratio", "true", "0", "0", "0", "0", "0", "10")
	critical := otelcolExporterRuntimeResource("critical-ratio", "true", "0", "0", "0", "0", "0", "20")
	for _, resource := range []*model.Resource{&below, &critical} {
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] = "true"
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds] = "60"
		resource.Metadata[model.MetadataOTelExporterSendFailureDelta] = "10"
		resource.Metadata[model.MetadataOTelExporterSentMetricsAvailable] = "true"
		resource.Metadata[model.MetadataOTelExporterSentTelemetryDelta] = "90"
		resource.Metadata[model.MetadataOTelExporterSendFailureRatioEvaluable] = "true"
	}
	below.Metadata[model.MetadataOTelExporterSendFailureRatioPercent] = "9.99"
	critical.Metadata[model.MetadataOTelExporterSendFailureRatioPercent] = "10"
	for _, resource := range []model.Resource{below, critical} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	sendFindings, err := NewOTelExporterSendFailuresAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(sendFindings) != 1 || sendFindings[0].Resource.ID != below.ID {
		t.Fatalf("expected only below-threshold Warning: findings=%#v err=%v", sendFindings, err)
	}
	highFindings, err := NewOTelExporterHighSendFailureRatioAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(highFindings) != 1 ||
		highFindings[0].Resource.ID != critical.ID ||
		highFindings[0].Type != "OTelExporterHighSendFailureRatio" ||
		highFindings[0].Severity != model.SeverityCritical ||
		highFindings[0].Category != model.FindingCategoryReliability ||
		highFindings[0].Metadata["failure_ratio_percent"] != "10" ||
		!strings.Contains(highFindings[0].Evidence[0], "10% failure ratio") {
		t.Fatalf("expected only threshold Critical: findings=%#v err=%v", highFindings, err)
	}
}

func otelcolExporterRuntimeResource(id, available, enqueueLogs, enqueueMetrics, enqueueSpans, sendLogs, sendMetrics, sendSpans string) model.Resource {
	return model.Resource{
		ID:     "otelcol-exporter-runtime-" + id,
		Type:   model.ResourceTypeInstance,
		Name:   "Collector " + id,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "otelcol", ExternalID: id},
		Metadata: map[string]string{
			model.MetadataOTelRuntimeMetricsAvailable:           available,
			model.MetadataOTelExporterEnqueueFailedLogRecords:   enqueueLogs,
			model.MetadataOTelExporterEnqueueFailedMetricPoints: enqueueMetrics,
			model.MetadataOTelExporterEnqueueFailedSpans:        enqueueSpans,
			model.MetadataOTelExporterSendFailedLogRecords:      sendLogs,
			model.MetadataOTelExporterSendFailedMetricPoints:    sendMetrics,
			model.MetadataOTelExporterSendFailedSpans:           sendSpans,
		},
	}
}
