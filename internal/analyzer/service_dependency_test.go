package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestServiceDependencyAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	services := []model.Resource{
		{ID: "service-a", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive},
		{ID: "service-b", Type: model.ResourceTypeService, Name: "billing", Status: model.ResourceStatusActive},
		{ID: "service-c", Type: model.ResourceTypeService, Name: "catalog", Status: model.ResourceStatusActive},
		{ID: "service-d", Type: model.ResourceTypeService, Name: "deprecated", Status: model.ResourceStatusDeprecated},
	}
	for _, service := range services {
		if err := store.Resources.Upsert(ctx, service); err != nil {
			t.Fatalf("upsert service: %v", err)
		}
	}
	relationships := []model.Relationship{
		serviceDependencyRelationship("a-b", "service-a", "service-b", "5"),
		serviceDependencyRelationship("a-c", "service-a", "service-c", "7"),
		serviceDependencyRelationship("b-a", "service-b", "service-a", "3"),
		serviceDependencyRelationship("a-d", "service-a", "service-d", "100"),
	}
	for _, relationship := range relationships {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	analysis := Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"service_dependency_fanout_threshold": 1},
	}

	fanout, err := NewHighServiceDependencyFanoutAnalyzer().Execute(ctx, analysis)
	if err != nil {
		t.Fatalf("execute fanout analyzer: %v", err)
	}
	if len(fanout) != 1 || fanout[0].Resource.ID != "service-a" ||
		fanout[0].Metadata["dependency_count"] != "2" ||
		fanout[0].Metadata["call_count"] != "12" {
		t.Fatalf("unexpected fanout findings: %#v", fanout)
	}

	cycles, err := NewCircularServiceDependencyAnalyzer().Execute(ctx, analysis)
	if err != nil {
		t.Fatalf("execute cycle analyzer: %v", err)
	}
	if len(cycles) != 1 || cycles[0].Resource.ID != "service-a" ||
		cycles[0].Metadata["service_count"] != "2" ||
		cycles[0].Metadata["edge_count"] != "2" ||
		cycles[0].Metadata["call_count"] != "8" ||
		cycles[0].Category != model.FindingCategoryReliability {
		t.Fatalf("unexpected cycle findings: %#v", cycles)
	}
}

func TestCircularServiceDependencyAnalyzerDetectsSelfLoop(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	service := model.Resource{ID: "service-loop", Type: model.ResourceTypeService, Name: "loop", Status: model.ResourceStatusActive}
	if err := store.Resources.Upsert(ctx, service); err != nil {
		t.Fatalf("upsert service: %v", err)
	}
	if err := store.Relationships.Upsert(ctx, serviceDependencyRelationship("self", service.ID, service.ID, "1")); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewCircularServiceDependencyAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil || len(findings) != 1 || findings[0].Metadata["service_count"] != "1" {
		t.Fatalf("unexpected self-loop findings: %#v, %v", findings, err)
	}
}

func serviceDependencyRelationship(id, fromID, toID, callCount string) model.Relationship {
	return model.Relationship{
		ID:     id,
		FromID: fromID,
		ToID:   toID,
		Type:   model.RelationshipDependsOn,
		Metadata: map[string]string{
			model.MetadataAPMTopologyCallCount: callCount,
		},
	}
}
