package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelCollectorRuntimeUnhealthyAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		otelcolRuntimeResource("unhealthy", "true", "false"),
		otelcolRuntimeResource("healthy", "true", "true"),
		otelcolRuntimeResource("unavailable", "false", "false"),
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	notRuntime := otelcolRuntimeResource("config-only", "true", "false")
	delete(notRuntime.Metadata, model.MetadataOTelCollectorRuntime)
	if err := store.Resources.Upsert(ctx, notRuntime); err != nil {
		t.Fatalf("upsert config-only resource: %v", err)
	}

	findings, err := NewOTelCollectorRuntimeUnhealthyAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one unhealthy runtime finding, got %#v", findings)
	}
	if findings[0].Resource.ID != "otelcol-unhealthy" ||
		findings[0].Type != "OTelCollectorRuntimeUnhealthy" ||
		findings[0].Severity != model.SeverityCritical ||
		findings[0].Category != model.FindingCategoryReliability {
		t.Fatalf("unexpected runtime finding: %#v", findings[0])
	}
}

func otelcolRuntimeResource(id string, available string, healthy string) model.Resource {
	return model.Resource{
		ID:     "otelcol-" + id,
		Type:   model.ResourceTypeInstance,
		Name:   "Collector " + id,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "otelcol", ExternalID: id},
		Metadata: map[string]string{
			model.MetadataOTelCollectorRuntime:       "true",
			model.MetadataOTelRuntimeHealthAvailable: available,
			model.MetadataOTelRuntimeHealthy:         healthy,
		},
	}
}
