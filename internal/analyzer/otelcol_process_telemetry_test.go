package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelCollectorProcessTelemetryIncompleteAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	incomplete := otelcolProcessTelemetryResource("incomplete", "true", "4")
	complete := otelcolProcessTelemetryResource("complete", "true", "0")
	unobserved := otelcolProcessTelemetryResource("unobserved", "false", "6")
	allMissing := otelcolProcessTelemetryResource("all-missing", "true", "6")
	invalid := otelcolProcessTelemetryResource("invalid", "true", "private-count")
	unavailable := otelcolProcessTelemetryResource("unavailable", "true", "4")
	unavailable.Metadata[model.MetadataOTelRuntimeMetricsAvailable] = "false"
	wrongSource := otelcolProcessTelemetryResource("wrong-source", "true", "4")
	wrongSource.Source.System = "plugin"
	inactive := otelcolProcessTelemetryResource("inactive", "true", "4")
	inactive.Status = model.ResourceStatusOrphan
	for _, resource := range []model.Resource{
		incomplete,
		complete,
		unobserved,
		allMissing,
		invalid,
		unavailable,
		wrongSource,
		inactive,
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewOTelCollectorProcessTelemetryIncompleteAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 ||
		findings[0].Resource.ID != incomplete.ID ||
		findings[0].Type != "OTelCollectorProcessTelemetryIncomplete" ||
		findings[0].Severity != model.SeverityWarning ||
		findings[0].Category != model.FindingCategoryConfiguration ||
		findings[0].Metadata["available_metric_count"] != "2" ||
		findings[0].Metadata["expected_metric_count"] != "6" ||
		findings[0].Metadata["missing_metric_count"] != "4" ||
		!strings.Contains(findings[0].Evidence[0], "exposes 2 of 6") {
		t.Fatalf("unexpected process telemetry findings: %#v err=%v", findings, err)
	}
	encoded, err := json.Marshal(findings[0])
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	for _, privateValue := range []string{"private-instance", "private-label", "private-count", `"268435456"`} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("finding leaked %q: %s", privateValue, encoded)
		}
	}
}

func otelcolProcessTelemetryResource(id, observed, missingCount string) model.Resource {
	return model.Resource{
		ID:     "otelcol-process-telemetry-" + id,
		Type:   model.ResourceTypeInstance,
		Name:   "Collector " + id,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "otelcol", ExternalID: id},
		Metadata: map[string]string{
			model.MetadataOTelRuntimeMetricsAvailable:      "true",
			model.MetadataOTelProcessTelemetryObserved:     observed,
			model.MetadataOTelProcessTelemetryMissingCount: missingCount,
		},
	}
}
