package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelReceiverRefusedTelemetryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	refused := otelcolReceiverRuntimeResource("refused", "true", "2", "3", "4")
	healthy := otelcolReceiverRuntimeResource("healthy", "true", "0", "0", "0")
	unavailable := otelcolReceiverRuntimeResource("unavailable", "false", "2", "3", "4")
	inactive := otelcolReceiverRuntimeResource("inactive", "true", "2", "3", "4")
	inactive.Status = model.ResourceStatusDeprecated
	wrongSource := otelcolReceiverRuntimeResource("wrong-source", "true", "2", "3", "4")
	wrongSource.Source.System = "plugin"
	for _, resource := range []model.Resource{refused, healthy, unavailable, inactive, wrongSource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	item := NewOTelReceiverRefusedTelemetryAnalyzer()
	findings, err := item.Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Resource.ID != refused.ID ||
		findings[0].Type != "OTelReceiverRefusedTelemetry" ||
		findings[0].Severity != model.SeverityWarning ||
		findings[0].Category != model.FindingCategoryReliability ||
		!strings.Contains(findings[0].Evidence[0], "2 refused log record(s), 3 metric point(s), and 4 span(s)") ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	encoded, err := json.Marshal(findings[0])
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	for _, privateValue := range []string{"private-receiver", "private-instance", "private-label"} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("finding leaked %q: %s", privateValue, encoded)
		}
	}
}

func TestOTelReceiverRefusedTelemetryAnalyzerPrefersCounterDelta(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	stable := otelcolReceiverRuntimeResource("stable-delta", "true", "2", "3", "4")
	growing := otelcolReceiverRuntimeResource("growing-delta", "true", "3", "3", "4")
	for _, resource := range []*model.Resource{&stable, &growing} {
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] = "true"
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds] = "60"
	}
	stable.Metadata[model.MetadataOTelReceiverRefusedDelta] = "0"
	growing.Metadata[model.MetadataOTelReceiverRefusedDelta] = "1"
	for _, resource := range []model.Resource{stable, growing} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewOTelReceiverRefusedTelemetryAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != growing.ID ||
		findings[0].Metadata["counter_evidence"] != "delta" ||
		findings[0].Metadata["counter_delta"] != "1" {
		t.Fatalf("unexpected receiver delta finding: findings=%#v err=%v", findings, err)
	}
}

func TestOTelReceiverRefusalAnalyzersAreMutuallyExclusiveAtRatioThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	below := otelcolReceiverRuntimeResource("below-ratio", "true", "0", "0", "10")
	critical := otelcolReceiverRuntimeResource("critical-ratio", "true", "0", "0", "20")
	for _, resource := range []*model.Resource{&below, &critical} {
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] = "true"
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds] = "60"
		resource.Metadata[model.MetadataOTelReceiverRefusedDelta] = "10"
		resource.Metadata[model.MetadataOTelReceiverAcceptedMetricsAvailable] = "true"
		resource.Metadata[model.MetadataOTelReceiverAcceptedTelemetryDelta] = "90"
		resource.Metadata[model.MetadataOTelReceiverRefusalRatioEvaluable] = "true"
	}
	below.Metadata[model.MetadataOTelReceiverRefusalRatioPercent] = "9.99"
	critical.Metadata[model.MetadataOTelReceiverRefusalRatioPercent] = "10"
	for _, resource := range []model.Resource{below, critical} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	refusedFindings, err := NewOTelReceiverRefusedTelemetryAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(refusedFindings) != 1 || refusedFindings[0].Resource.ID != below.ID {
		t.Fatalf("expected only below-threshold Warning: findings=%#v err=%v", refusedFindings, err)
	}
	highFindings, err := NewOTelReceiverHighRefusalRatioAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(highFindings) != 1 ||
		highFindings[0].Resource.ID != critical.ID ||
		highFindings[0].Type != "OTelReceiverHighRefusalRatio" ||
		highFindings[0].Severity != model.SeverityCritical ||
		highFindings[0].Category != model.FindingCategoryReliability ||
		highFindings[0].Metadata["refusal_ratio_percent"] != "10" ||
		!strings.Contains(highFindings[0].Evidence[0], "10% refusal ratio") {
		t.Fatalf("expected only threshold Critical: findings=%#v err=%v", highFindings, err)
	}
}

func otelcolReceiverRuntimeResource(id, available, logs, metrics, spans string) model.Resource {
	return model.Resource{
		ID:     "otelcol-receiver-runtime-" + id,
		Type:   model.ResourceTypeInstance,
		Name:   "Collector " + id,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "otelcol", ExternalID: id},
		Metadata: map[string]string{
			model.MetadataOTelRuntimeMetricsAvailable:     available,
			model.MetadataOTelReceiverRefusedLogRecords:   logs,
			model.MetadataOTelReceiverRefusedMetricPoints: metrics,
			model.MetadataOTelReceiverRefusedSpans:        spans,
		},
	}
}
