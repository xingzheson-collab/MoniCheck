package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUnusedDatasourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	usedDatasource := model.Resource{ID: "datasource-used", Type: model.ResourceTypeDatasource, Name: "Prometheus", Status: model.ResourceStatusActive}
	unusedDatasource := model.Resource{ID: "datasource-unused", Type: model.ResourceTypeDatasource, Name: "Old Prometheus", Status: model.ResourceStatusActive}
	inactiveOnlyDatasource := model.Resource{ID: "datasource-inactive-only", Type: model.ResourceTypeDatasource, Name: "Old Loki", Status: model.ResourceStatusActive}
	recordingOnlyDatasource := model.Resource{ID: "datasource-recording-only", Type: model.ResourceTypeDatasource, Name: "Recording Prometheus", Status: model.ResourceStatusActive}
	remoteReadDatasource := model.Resource{ID: "datasource-remote-read", Type: model.ResourceTypeDatasource, Name: "Remote Read", Status: model.ResourceStatusActive}
	deprecatedDatasource := model.Resource{ID: "datasource-deprecated", Type: model.ResourceTypeDatasource, Name: "Deprecated Prometheus", Status: model.ResourceStatusDeprecated}
	panel := model.Resource{ID: "panel-1", Type: model.ResourceTypePanel, Name: "Request Rate", Status: model.ResourceStatusActive}
	recordingRule := model.Resource{ID: "recording-1", Type: model.ResourceTypeRecordingRule, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive}
	tsdb := model.Resource{ID: "tsdb-1", Type: model.ResourceTypeTSDB, Name: "Prometheus", Status: model.ResourceStatusActive}
	inactivePanel := model.Resource{ID: "panel-old", Type: model.ResourceTypePanel, Name: "Old Panel", Status: model.ResourceStatusDeprecated}

	for _, resource := range []model.Resource{usedDatasource, unusedDatasource, inactiveOnlyDatasource, recordingOnlyDatasource, remoteReadDatasource, deprecatedDatasource, panel, recordingRule, tsdb, inactivePanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "panel-datasource", FromID: panel.ID, ToID: usedDatasource.ID, Type: model.RelationshipUses},
		{ID: "recording-datasource", FromID: recordingRule.ID, ToID: recordingOnlyDatasource.ID, Type: model.RelationshipUses},
		{ID: "tsdb-remote-read", FromID: tsdb.ID, ToID: remoteReadDatasource.ID, Type: model.RelationshipUses},
		{ID: "inactive-panel-datasource", FromID: inactivePanel.ID, ToID: inactiveOnlyDatasource.ID, Type: model.RelationshipUses},
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

	findings, err := NewUnusedDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
	}
	if !found[unusedDatasource.ID] || !found[inactiveOnlyDatasource.ID] {
		t.Fatalf("expected unused datasource findings for %s and %s, got %#v", unusedDatasource.ID, inactiveOnlyDatasource.ID, findings)
	}
	if found[recordingOnlyDatasource.ID] {
		t.Fatalf("did not expect datasource used by recording rule to be unused, got %#v", findings)
	}
	if found[remoteReadDatasource.ID] {
		t.Fatalf("did not expect datasource used by TSDB remote read to be unused, got %#v", findings)
	}
	if found[deprecatedDatasource.ID] {
		t.Fatalf("did not expect deprecated datasource finding, got %#v", findings)
	}
}

func TestUnusedDatasourceAnalyzerWithoutGraph(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	if err := store.Resources.Upsert(ctx, model.Resource{ID: "datasource-unused", Type: model.ResourceTypeDatasource, Name: "Old Prometheus", Status: model.ResourceStatusActive}); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewUnusedDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings without graph, got %#v", findings)
	}
}
