package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDirectDatasourceAccessAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	proxyDatasource := model.Resource{
		ID:     "datasource-proxy",
		Type:   model.ResourceTypeDatasource,
		Name:   "Proxy Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceUID:    "proxy-prom",
			model.MetadataDatasourceAccess: "proxy",
		},
	}
	directDatasource := model.Resource{
		ID:     "datasource-direct",
		Type:   model.ResourceTypeDatasource,
		Name:   "Direct Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceUID:    "direct-prom",
			model.MetadataDatasourceAccess: "direct",
		},
	}
	browserDatasource := model.Resource{
		ID:     "datasource-browser",
		Type:   model.ResourceTypeDatasource,
		Name:   "Browser Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceUID:    "browser-prom",
			model.MetadataDatasourceAccess: "browser",
		},
	}
	for _, resource := range []model.Resource{proxyDatasource, directDatasource, browserDatasource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewDirectDatasourceAccessAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		if finding.Type != "DirectDatasourceAccess" {
			t.Fatalf("expected DirectDatasourceAccess, got %s", finding.Type)
		}
	}
	if !found[directDatasource.ID] || !found[browserDatasource.ID] {
		t.Fatalf("expected direct and browser datasource findings, got %#v", found)
	}
}

func TestDirectDatasourceAccessAnalyzerAllowlist(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	datasource := model.Resource{
		ID:     "datasource-direct",
		Type:   model.ResourceTypeDatasource,
		Name:   "Direct Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceUID:    "direct-prom",
			model.MetadataDatasourceAccess: "direct",
		},
	}
	if err := store.Resources.Upsert(ctx, datasource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewDirectDatasourceAccessAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"allowed_direct_datasource_access": "direct-prom",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
