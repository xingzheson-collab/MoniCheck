package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelReceiverSecurityAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pipeline := otelResource(model.ResourceTypePipeline, "traces", "pipeline:traces")
	unsafe := otelReceiverSecurityTestResource("otlp/unsafe", "1", "1")
	safe := otelReceiverSecurityTestResource("otlp/safe", "0", "0")
	unevaluable := otelReceiverSecurityTestResource("otlp/unevaluable", "", "")
	unmarked := otelReceiverSecurityTestResource("otlp/unmarked", "1", "1")
	delete(unmarked.Metadata, model.MetadataOTelReceiverNetworkSafety)
	unused := otelReceiverSecurityTestResource("otlp/unused", "1", "1")
	wrongSource := otelReceiverSecurityTestResource("otlp/wrong-source", "1", "1")
	wrongSource.Source.System = "plugin"
	inactive := otelReceiverSecurityTestResource("otlp/inactive", "1", "1")
	inactive.Status = model.ResourceStatusDeprecated
	for _, resource := range []model.Resource{pipeline, unsafe, safe, unevaluable, unmarked, unused, wrongSource, inactive} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, receiver := range []model.Resource{unsafe, safe, unevaluable, unmarked, wrongSource, inactive} {
		if err := store.Relationships.Upsert(ctx, model.Relationship{
			ID:     "pipeline-uses-" + receiver.ID,
			FromID: pipeline.ID,
			ToID:   receiver.ID,
			Type:   model.RelationshipUses,
		}); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	tests := []struct {
		analyzer     Analyzer
		findingType  string
		evidencePart string
	}{
		{NewOTelReceiverPublicUnauthenticatedAnalyzer(), "OTelReceiverPublicUnauthenticated", "without a configured authenticator"},
		{NewOTelReceiverPublicPlaintextAnalyzer(), "OTelReceiverPublicPlaintext", "without a complete TLS certificate"},
	}
	for _, test := range tests {
		t.Run(test.analyzer.ID(), func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if len(findings) != 1 ||
				findings[0].Resource.ID != unsafe.ID ||
				findings[0].Type != test.findingType ||
				findings[0].Severity != model.SeverityCritical ||
				findings[0].Category != model.FindingCategorySecurity ||
				!strings.Contains(findings[0].Evidence[0], test.evidencePart) ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategorySecurity {
				t.Fatalf("unexpected receiver security findings: %#v", findings)
			}
		})
	}
}

func otelReceiverSecurityTestResource(name string, unauthenticated string, plaintext string) model.Resource {
	resource := otelResource(model.ResourceTypeReceiver, name, "receiver:"+name)
	resource.Metadata[model.MetadataComponentKind] = "receiver"
	resource.Metadata[model.MetadataComponentType] = "otlp"
	resource.Metadata[model.MetadataOTelReceiverNetworkSafety] = "true"
	if unauthenticated != "" {
		resource.Metadata[model.MetadataOTelReceiverPublicUnauthenticatedCnt] = unauthenticated
	}
	if plaintext != "" {
		resource.Metadata[model.MetadataOTelReceiverPublicPlaintextCount] = plaintext
	}
	return resource
}
