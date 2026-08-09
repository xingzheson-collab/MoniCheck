package analyzer

import (
	"context"
	"fmt"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestHighOperationCountServiceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	service := model.Resource{
		ID:     "service-checkout",
		Type:   model.ResourceTypeService,
		Name:   "checkout",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataOperationDiscoveryAvailable: "true",
			model.MetadataOperationDiscoveryTruncated: "true",
			model.MetadataOperationCount:              "100",
		},
	}
	quietService := model.Resource{ID: "service-quiet", Type: model.ResourceTypeService, Name: "quiet", Status: model.ResourceStatusActive}
	for _, resource := range []model.Resource{service, quietService} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert service: %v", err)
		}
	}
	for i := 0; i < 4; i++ {
		operation := model.Resource{
			ID:     fmt.Sprintf("checkout-op-%d", i),
			Type:   model.ResourceTypeTraceOperation,
			Name:   fmt.Sprintf("GET /checkout/%d", i),
			Status: model.ResourceStatusActive,
		}
		if err := store.Resources.Upsert(ctx, operation); err != nil {
			t.Fatalf("upsert operation: %v", err)
		}
		if err := store.Relationships.Upsert(ctx, model.Relationship{ID: "rel-" + operation.ID, FromID: operation.ID, ToID: service.ID, Type: model.RelationshipBelongsTo}); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	quietOperation := model.Resource{ID: "quiet-op", Type: model.ResourceTypeTraceOperation, Name: "GET /health", Status: model.ResourceStatusActive}
	if err := store.Resources.Upsert(ctx, quietOperation); err != nil {
		t.Fatalf("upsert quiet operation: %v", err)
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{ID: "rel-quiet", FromID: quietOperation.ID, ToID: quietService.ID, Type: model.RelationshipBelongsTo}); err != nil {
		t.Fatalf("upsert quiet relationship: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewHighOperationCountServiceAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"trace_operation_count_threshold": 3},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != service.ID ||
		findings[0].Metadata["operation_count"] != "100" ||
		findings[0].Metadata["catalog_truncated"] != "true" {
		t.Fatalf("expected checkout finding, got %#v", findings)
	}
}
