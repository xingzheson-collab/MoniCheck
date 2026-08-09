package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestStaleAlertUpdateAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	freshAlert := model.Resource{
		ID:     "alert-fresh",
		Type:   model.ResourceTypeAlert,
		Name:   "FreshAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:fresh"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			model.MetadataUpdatedAt:  time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339),
		},
	}
	staleAlert := model.Resource{
		ID:     "alert-stale",
		Type:   model.ResourceTypeAlert,
		Name:   "StaleAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:stale"},
		Metadata: map[string]string{
			model.MetadataAlertState: "firing",
			model.MetadataUpdatedAt:  time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
		},
	}
	staleN9EAlert := model.Resource{
		ID:     "n9e-alert-stale",
		Type:   model.ResourceTypeAlert,
		Name:   "N9EStaleAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "n9e", Instance: "local", ExternalID: "alert:n9e-stale"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			model.MetadataUpdatedAt:  time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
		},
	}
	suppressedAlert := model.Resource{
		ID:     "alert-suppressed",
		Type:   model.ResourceTypeAlert,
		Name:   "SuppressedAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:suppressed"},
		Metadata: map[string]string{
			model.MetadataAlertState: "suppressed",
			model.MetadataUpdatedAt:  time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
		},
	}
	prometheusAlert := model.Resource{
		ID:     "prometheus-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "PrometheusAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "alert:prom"},
		Metadata: map[string]string{
			model.MetadataUpdatedAt: time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
		},
	}
	deprecatedAlert := model.Resource{
		ID:     "deprecated-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "DeprecatedAlert",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:deprecated"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			model.MetadataUpdatedAt:  time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
		},
	}
	for _, resource := range []model.Resource{freshAlert, staleAlert, staleN9EAlert, suppressedAlert, prometheusAlert, deprecatedAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewStaleAlertUpdateAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	found := map[string]bool{}
	for _, finding := range findings {
		if finding.Type != "StaleAlertUpdate" {
			t.Fatalf("unexpected finding: %#v", finding)
		}
		found[finding.Resource.ID] = true
	}
	if !found[staleAlert.ID] || !found[staleN9EAlert.ID] {
		t.Fatalf("expected stale findings for Alertmanager and N9E, got %#v", findings)
	}
}

func TestStaleAlertUpdateAnalyzerCustomThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	alert := model.Resource{
		ID:     "alert-custom-threshold",
		Type:   model.ResourceTypeAlert,
		Name:   "CustomThresholdAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:custom"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			model.MetadataUpdatedAt:  time.Now().UTC().Add(-20 * time.Minute).Format(time.RFC3339),
		},
	}
	if err := store.Resources.Upsert(ctx, alert); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewStaleAlertUpdateAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"stale_alert_update_threshold": 10 * time.Minute},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != alert.ID {
		t.Fatalf("expected finding for %s, got %#v", alert.ID, findings)
	}
}
