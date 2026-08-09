package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestRiskyTraceTagAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{ID: "tag-service", Type: model.ResourceTypeTraceTag, Name: "service.name", Status: model.ResourceStatusActive},
		{ID: "tag-user", Type: model.ResourceTypeTraceTag, Name: "user.id", Status: model.ResourceStatusActive},
		{ID: "tag-request", Type: model.ResourceTypeTraceTag, Name: "request-id", Status: model.ResourceStatusActive},
		{ID: "tag-deprecated-session", Type: model.ResourceTypeTraceTag, Name: "session_id", Status: model.ResourceStatusDeprecated},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewRiskyTraceTagAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %#v", findings)
	}
	if findings[0].Resource.Name != "request-id" || findings[1].Resource.Name != "user.id" {
		t.Fatalf("expected sorted risky trace tag findings, got %#v", findings)
	}
	if findings[1].Metadata["normalized_tag"] != "user_id" {
		t.Fatalf("expected normalized metadata, got %#v", findings[1].Metadata)
	}
}

func TestRiskyTraceTagAnalyzerCustomNames(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := model.Resource{
		ID:     "trace-tag-tenant",
		Type:   model.ResourceTypeTraceTag,
		Name:   "tenant.slug",
		Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	findings, err := NewRiskyTraceTagAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"risky_trace_tag_names": []string{"tenant_slug"}},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != resource.ID {
		t.Fatalf("expected custom risky tag finding, got %#v", findings)
	}
}
