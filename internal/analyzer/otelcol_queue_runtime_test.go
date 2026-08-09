package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelExporterQueueSaturatedAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	saturated := otelcolQueueRuntimeResource("saturated", "true", "3", "2", "125")
	healthy := otelcolQueueRuntimeResource("healthy", "true", "3", "0", "80")
	unobserved := otelcolQueueRuntimeResource("unobserved", "true", "0", "2", "125")
	unavailable := otelcolQueueRuntimeResource("unavailable", "false", "3", "2", "125")
	wrongSource := otelcolQueueRuntimeResource("wrong-source", "true", "3", "2", "125")
	wrongSource.Source.System = "plugin"
	for _, resource := range []model.Resource{saturated, healthy, unobserved, unavailable, wrongSource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	item := NewOTelExporterQueueSaturatedAnalyzer()
	findings, err := item.Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Resource.ID != saturated.ID ||
		findings[0].Type != "OTelExporterQueueSaturated" ||
		findings[0].Severity != model.SeverityWarning ||
		findings[0].Category != model.FindingCategoryReliability ||
		!strings.Contains(findings[0].Evidence[0], "2 saturated exporter sending queue(s) across 3 evaluable queue(s)") ||
		!strings.Contains(findings[0].Evidence[0], "125%") ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	encoded, err := json.Marshal(findings[0])
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	for _, privateValue := range []string{"private-exporter", "private-instance", "private-label", "queue-capacity"} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("finding leaked %q: %s", privateValue, encoded)
		}
	}
}

func otelcolQueueRuntimeResource(id, available, observed, saturated, maxUtilization string) model.Resource {
	return model.Resource{
		ID:     "otelcol-queue-runtime-" + id,
		Type:   model.ResourceTypeInstance,
		Name:   "Collector " + id,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "otelcol", ExternalID: id},
		Metadata: map[string]string{
			model.MetadataOTelRuntimeMetricsAvailable:            available,
			model.MetadataOTelExporterQueueObservedCount:         observed,
			model.MetadataOTelExporterQueueSaturatedCount:        saturated,
			model.MetadataOTelExporterQueueMaxUtilizationPercent: maxUtilization,
		},
	}
}
