package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestJaegerRuntimeUnhealthyAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	unhealthy := jaegerRuntimeResource("unhealthy", "true", "false")
	healthy := jaegerRuntimeResource("healthy", "true", "true")
	unevaluable := jaegerRuntimeResource("unevaluable", "false", "false")
	deprecated := jaegerRuntimeResource("deprecated", "true", "false")
	deprecated.Status = model.ResourceStatusDeprecated
	otherSystem := jaegerRuntimeResource("other-system", "true", "false")
	otherSystem.Source.System = "other"
	notRuntime := jaegerRuntimeResource("not-runtime", "true", "false")
	delete(notRuntime.Metadata, model.MetadataJaegerRuntime)
	for _, resource := range []model.Resource{unhealthy, healthy, unevaluable, deprecated, otherSystem, notRuntime} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewJaegerRuntimeUnhealthyAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one Jaeger unhealthy finding, got %#v", findings)
	}
	finding := findings[0]
	if finding.Resource.ID != unhealthy.ID ||
		finding.Type != "JaegerRuntimeUnhealthy" ||
		finding.Severity != model.SeverityCritical ||
		finding.Category != model.FindingCategoryReliability {
		t.Fatalf("unexpected Jaeger unhealthy finding: %#v", finding)
	}
}

func jaegerRuntimeResource(id, available, healthy string) model.Resource {
	return model.Resource{
		ID:     id,
		Type:   model.ResourceTypeInstance,
		Name:   "Jaeger Runtime",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "jaeger", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataJaegerRuntime:         "true",
			model.MetadataJaegerHealthAvailable: available,
			model.MetadataJaegerHealthy:         healthy,
			model.MetadataJaegerHealthSource:    "healthcheckv2",
		},
	}
}
