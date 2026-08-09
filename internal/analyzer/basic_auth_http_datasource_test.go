package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBasicAuthHTTPDatasourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	httpsBasicAuth := model.Resource{
		ID:     "datasource-https-basic-auth",
		Type:   model.ResourceTypeDatasource,
		Name:   "HTTPS Basic Auth",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceURL:       "https://prometheus.example.com",
			model.MetadataDatasourceBasicAuth: "true",
		},
	}
	httpNoBasicAuth := model.Resource{
		ID:     "datasource-http-no-basic-auth",
		Type:   model.ResourceTypeDatasource,
		Name:   "HTTP No Basic Auth",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceURL:       "http://prometheus.internal:9090",
			model.MetadataDatasourceBasicAuth: "false",
		},
	}
	httpBasicAuth := model.Resource{
		ID:     "datasource-http-basic-auth",
		Type:   model.ResourceTypeDatasource,
		Name:   "HTTP Basic Auth",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceUID:           "http-basic-auth",
			model.MetadataDatasourceURLConfigured: "true",
			model.MetadataDatasourceURLValid:      "true",
			model.MetadataDatasourceURLScheme:     "http",
			model.MetadataDatasourceURLHostScope:  "internal",
			model.MetadataDatasourceBasicAuth:     "true",
		},
	}
	for _, resource := range []model.Resource{httpsBasicAuth, httpNoBasicAuth, httpBasicAuth} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewBasicAuthHTTPDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "BasicAuthHTTPDatasource" {
		t.Fatalf("expected BasicAuthHTTPDatasource, got %s", findings[0].Type)
	}
	if findings[0].Resource.ID != httpBasicAuth.ID {
		t.Fatalf("expected HTTP basic auth datasource finding, got %s", findings[0].Resource.ID)
	}
	if strings.Contains(strings.Join(findings[0].Evidence, " "), "prometheus.internal") ||
		findings[0].Metadata[model.MetadataDatasourceURL] != "" {
		t.Fatalf("finding must not retain the datasource URL: %#v", findings[0])
	}
}

func TestBasicAuthHTTPDatasourceAnalyzerAllowlist(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	datasource := model.Resource{
		ID:     "datasource-http-basic-auth",
		Type:   model.ResourceTypeDatasource,
		Name:   "HTTP Basic Auth",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceUID:       "http-basic-auth",
			model.MetadataDatasourceURL:       "http://prometheus.internal:9090",
			model.MetadataDatasourceBasicAuth: "true",
		},
	}
	if err := store.Resources.Upsert(ctx, datasource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewBasicAuthHTTPDatasourceAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"allowed_basic_auth_http_datasources": "http-basic-auth",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
