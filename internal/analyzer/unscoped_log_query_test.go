package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUnscopedLogQueryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	scopedPanel := model.Resource{
		ID:     "panel-log-scoped",
		Type:   model.ResourceTypePanel,
		Name:   "Scoped Logs",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `{app="api"} |= "error"`,
			model.MetadataQueryLanguage: "logql",
		},
	}
	unscopedPanel := model.Resource{
		ID:     "panel-log-unscoped",
		Type:   model.ResourceTypePanel,
		Name:   "Unscoped Logs",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `sum(count_over_time({} |= "error" [5m]))`,
			model.MetadataQueryLanguage: "logql",
		},
	}
	nameOnlyPanel := model.Resource{
		ID:     "panel-name-only",
		Type:   model.ResourceTypePanel,
		Name:   "Name Only Logs",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `{__name__="logs"} |~ "timeout"`,
			model.MetadataQueryLanguage: "logql",
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
	for _, resource := range []model.Resource{scopedPanel, unscopedPanel, nameOnlyPanel, promPanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewUnscopedLogQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		if finding.Type != "UnscopedLogQuery" || finding.Severity != model.SeverityWarning {
			t.Fatalf("expected unscoped log query finding, got %#v", finding)
		}
	}
	if !found[unscopedPanel.ID] || !found[nameOnlyPanel.ID] || found[scopedPanel.ID] || found[promPanel.ID] {
		t.Fatalf("unexpected findings: %#v", found)
	}
}

func TestLogStreamSelectors(t *testing.T) {
	selectors := logStreamSelectors(`{app="api",message="literal } brace"} |= "error" or count_over_time({}[5m])`)
	if len(selectors) != 2 {
		t.Fatalf("expected 2 selectors, got %#v", selectors)
	}
	if selectors[0] != `{app="api",message="literal } brace"}` || selectors[1] != `{}` {
		t.Fatalf("unexpected selectors: %#v", selectors)
	}
}
