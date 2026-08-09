package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelCollectorRuntimeRestartAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	restarted := otelcolRuntimeRestartResource("restarted", "true", "true", "true")
	stable := otelcolRuntimeRestartResource("stable", "true", "true", "false")
	unevaluable := otelcolRuntimeRestartResource("unevaluable", "true", "false", "true")
	unavailable := otelcolRuntimeRestartResource("unavailable", "false", "true", "true")
	wrongSource := otelcolRuntimeRestartResource("wrong-source", "true", "true", "true")
	wrongSource.Source.System = "plugin"
	inactive := otelcolRuntimeRestartResource("inactive", "true", "true", "true")
	inactive.Status = model.ResourceStatusOrphan
	for _, resource := range []model.Resource{restarted, stable, unevaluable, unavailable, wrongSource, inactive} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewOTelCollectorRuntimeRestartAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 ||
		findings[0].Resource.ID != restarted.ID ||
		findings[0].Type != "OTelCollectorRuntimeRestart" ||
		findings[0].Severity != model.SeverityWarning ||
		findings[0].Category != model.FindingCategoryReliability ||
		findings[0].Metadata["restart_observed"] != "true" ||
		findings[0].Metadata["counter_interval_seconds"] != "60" ||
		!strings.Contains(findings[0].Evidence[0], "uptime counter moved backwards") {
		t.Fatalf("unexpected restart findings: %#v err=%v", findings, err)
	}
	encoded, err := json.Marshal(findings[0])
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	for _, privateValue := range []string{"private-instance", "private-label", `"3600"`} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("finding leaked %q: %s", privateValue, encoded)
		}
	}
}

func otelcolRuntimeRestartResource(id, uptimeAvailable, evaluable, observed string) model.Resource {
	return model.Resource{
		ID:     "otelcol-runtime-restart-" + id,
		Type:   model.ResourceTypeInstance,
		Name:   "Collector " + id,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "otelcol", ExternalID: id},
		Metadata: map[string]string{
			model.MetadataOTelRuntimeMetricsAvailable:            "true",
			model.MetadataOTelRuntimeCounterDeltaAvailable:       "true",
			model.MetadataOTelRuntimeCounterDeltaIntervalSeconds: "60",
			model.MetadataOTelProcessUptimeMetricsAvailable:      uptimeAvailable,
			model.MetadataOTelRuntimeRestartEvaluable:            evaluable,
			model.MetadataOTelRuntimeRestartObserved:             observed,
		},
	}
}
