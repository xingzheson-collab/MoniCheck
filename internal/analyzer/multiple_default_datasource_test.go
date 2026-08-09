package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMultipleDefaultDatasourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	firstDefault := model.Resource{
		ID:     "datasource-default-a",
		Type:   model.ResourceTypeDatasource,
		Name:   "Prometheus A",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "http://grafana.example", ExternalID: "datasource:prom-a"},
		Metadata: map[string]string{
			model.MetadataDatasourceDefault: "true",
		},
	}
	secondDefault := model.Resource{
		ID:     "datasource-default-b",
		Type:   model.ResourceTypeDatasource,
		Name:   "Prometheus B",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "http://grafana.example", ExternalID: "datasource:prom-b"},
		Metadata: map[string]string{
			model.MetadataDatasourceDefault: "true",
		},
	}
	otherInstanceDefault := model.Resource{
		ID:     "datasource-other-instance",
		Type:   model.ResourceTypeDatasource,
		Name:   "Other Grafana Prometheus",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "http://grafana-other.example", ExternalID: "datasource:prom"},
		Metadata: map[string]string{
			model.MetadataDatasourceDefault: "true",
		},
	}
	unknownDefault := model.Resource{
		ID:       "datasource-unknown-default",
		Type:     model.ResourceTypeDatasource,
		Name:     "Unknown Default",
		Status:   model.ResourceStatusActive,
		Source:   model.SourceInfo{System: "grafana", Instance: "http://grafana.example", ExternalID: "datasource:unknown"},
		Metadata: map[string]string{},
	}
	for _, resource := range []model.Resource{firstDefault, secondDefault, otherInstanceDefault, unknownDefault} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewMultipleDefaultDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		if finding.Type != "MultipleDefaultDatasource" {
			t.Fatalf("expected MultipleDefaultDatasource, got %s", finding.Type)
		}
		if finding.Metadata["default_datasources"] != "Prometheus A,Prometheus B" {
			t.Fatalf("expected default datasource metadata, got %#v", finding.Metadata)
		}
	}
	if !found[firstDefault.ID] || !found[secondDefault.ID] {
		t.Fatalf("expected findings for both default datasources, got %#v", found)
	}
}

func TestMultipleDefaultDatasourceAnalyzerSingleDefault(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	datasource := model.Resource{
		ID:     "datasource-default",
		Type:   model.ResourceTypeDatasource,
		Name:   "Prometheus",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "http://grafana.example", ExternalID: "datasource:prom"},
		Metadata: map[string]string{
			model.MetadataDatasourceDefault: "true",
		},
	}
	if err := store.Resources.Upsert(ctx, datasource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewMultipleDefaultDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
