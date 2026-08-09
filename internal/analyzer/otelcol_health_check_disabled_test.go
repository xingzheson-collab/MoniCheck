package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelCollectorHealthCheckDisabledAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		otelCollectorInstance("missing", "2", "false"),
		otelCollectorInstance("covered", "1", "true"),
		otelCollectorInstance("empty", "0", "false"),
	}
	wrongSource := otelCollectorInstance("wrong-source", "2", "false")
	wrongSource.Source.System = "prometheus"
	deprecated := otelCollectorInstance("deprecated", "2", "false")
	deprecated.Status = model.ResourceStatusDeprecated
	resources = append(resources, wrongSource, deprecated)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert instance: %v", err)
		}
	}

	findings, err := NewOTelCollectorHealthCheckDisabledAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Resource.ID != "missing" ||
		findings[0].Type != "OTelCollectorHealthCheckDisabled" ||
		findings[0].Severity != model.SeverityWarning ||
		findings[0].Category != model.FindingCategoryReliability ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected health-check findings: %#v", findings)
	}
}

func otelCollectorInstance(id, pipelineCount, healthEnabled string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeInstance,
		Name:   "OpenTelemetry Collector",
		Source: model.SourceInfo{System: "otelcol", Instance: "/etc/" + id + ".yaml"},
		Metadata: map[string]string{
			model.MetadataOTelCollectorConfigInstance: "true",
			model.MetadataOTelPipelineCount:           pipelineCount,
			model.MetadataOTelHealthCheckEnabled:      healthEnabled,
		},
		Status: model.ResourceStatusActive,
	}
}
