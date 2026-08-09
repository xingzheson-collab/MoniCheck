package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestInsecureDatasourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	internalHTTP := model.Resource{
		ID:       "datasource-internal-http",
		Type:     model.ResourceTypeDatasource,
		Name:     "Internal HTTP",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataDatasourceURL: "http://prometheus:9090"},
	}
	publicHTTPS := model.Resource{
		ID:       "datasource-public-https",
		Type:     model.ResourceTypeDatasource,
		Name:     "Public HTTPS",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataDatasourceURL: "https://prometheus.example.com"},
	}
	publicHTTP := model.Resource{
		ID:     "datasource-public-http",
		Type:   model.ResourceTypeDatasource,
		Name:   "Public HTTP",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceURLConfigured:      "true",
			model.MetadataDatasourceURLValid:           "true",
			model.MetadataDatasourceURLScheme:          "http",
			model.MetadataDatasourceURLHostScope:       "public",
			model.MetadataDatasourceURLHostFingerprint: datasourceHostFingerprint("prometheus.example.com"),
		},
	}
	allowedHTTP := model.Resource{
		ID:     "datasource-allowed-http",
		Type:   model.ResourceTypeDatasource,
		Name:   "Allowed HTTP",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceURLConfigured:      "true",
			model.MetadataDatasourceURLValid:           "true",
			model.MetadataDatasourceURLScheme:          "http",
			model.MetadataDatasourceURLHostScope:       "public",
			model.MetadataDatasourceURLHostFingerprint: datasourceHostFingerprint("metrics.example.com"),
		},
	}
	deprecatedPublicHTTP := model.Resource{
		ID:       "datasource-deprecated-public-http",
		Type:     model.ResourceTypeDatasource,
		Name:     "Deprecated Public HTTP",
		Status:   model.ResourceStatusDeprecated,
		Metadata: map[string]string{model.MetadataDatasourceURL: "http://deprecated.example.com"},
	}
	for _, resource := range []model.Resource{internalHTTP, publicHTTPS, publicHTTP, allowedHTTP, deprecatedPublicHTTP} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewInsecureDatasourceAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"allowed_insecure_datasource_hosts": "metrics.example.com"},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "InsecureDatasource" || findings[0].Resource.ID != publicHTTP.ID {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if strings.Contains(strings.Join(findings[0].Evidence, " "), "prometheus.example.com") {
		t.Fatalf("finding evidence must not disclose the datasource hostname: %#v", findings[0].Evidence)
	}
}
