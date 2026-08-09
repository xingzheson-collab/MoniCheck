package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUnscopedTraceQueryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	scopedPanel := model.Resource{
		ID:     "panel-trace-scoped",
		Type:   model.ResourceTypePanel,
		Name:   "Checkout Traces",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `{ resource.service.name = "checkout" && span.name =~ "GET.*" }`,
			model.MetadataQueryLanguage: "traceql",
		},
	}
	unscopedPanel := model.Resource{
		ID:     "panel-trace-unscoped",
		Type:   model.ResourceTypePanel,
		Name:   "All Traces",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `{}`,
			model.MetadataQueryLanguage: "traceql",
		},
	}
	promPanel := model.Resource{
		ID:     "panel-prom",
		Type:   model.ResourceTypePanel,
		Name:   "Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: `sum(rate(http_requests_total[5m]))`,
		},
	}
	for _, resource := range []model.Resource{scopedPanel, unscopedPanel, promPanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewUnscopedTraceQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "UnscopedTraceQuery" || findings[0].Resource.ID != unscopedPanel.ID || findings[0].Severity != model.SeverityWarning {
		t.Fatalf("expected unscoped trace query finding, got %#v", findings[0])
	}
}

func TestTraceQueryHasScope(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{query: `{}`, want: false},
		{query: `{ resource.service.name = "api" }`, want: true},
		{query: `{ span.duration > 500ms }`, want: true},
		{query: `{ status = error }`, want: true},
	}
	for _, tc := range cases {
		if got := traceQueryHasScope(tc.query); got != tc.want {
			t.Fatalf("traceQueryHasScope(%q)=%t, want %t", tc.query, got, tc.want)
		}
	}
}
