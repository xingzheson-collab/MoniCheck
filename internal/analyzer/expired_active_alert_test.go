package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestExpiredActiveAlertAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	freshAlert := model.Resource{
		ID:     "alert-fresh",
		Type:   model.ResourceTypeAlert,
		Name:   "FreshAlert",
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:fresh"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			model.MetadataEndsAt:     now.Add(time.Hour).Format(time.RFC3339),
		},
		Status: model.ResourceStatusActive,
	}
	expiredAlert := model.Resource{
		ID:     "alert-expired",
		Type:   model.ResourceTypeAlert,
		Name:   "ExpiredAlert",
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:expired"},
		Metadata: map[string]string{
			model.MetadataAlertState:   "active",
			model.MetadataFingerprint:  "expired-fingerprint",
			model.MetadataEndsAt:       now.Add(-time.Hour).Format(time.RFC3339),
			model.MetadataGeneratorURL: "http://prometheus/graph",
		},
		Status: model.ResourceStatusActive,
	}
	suppressedAlert := model.Resource{
		ID:     "alert-suppressed",
		Type:   model.ResourceTypeAlert,
		Name:   "SuppressedAlert",
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:suppressed"},
		Metadata: map[string]string{
			model.MetadataAlertState: "suppressed",
			model.MetadataEndsAt:     now.Add(-time.Hour).Format(time.RFC3339),
		},
		Status: model.ResourceStatusDeprecated,
	}
	prometheusAlert := model.Resource{
		ID:     "alert-prometheus",
		Type:   model.ResourceTypeAlert,
		Name:   "PrometheusAlert",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "alert:prometheus"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			model.MetadataEndsAt:     now.Add(-time.Hour).Format(time.RFC3339),
		},
		Status: model.ResourceStatusActive,
	}
	deprecatedActiveAlert := model.Resource{
		ID:     "alert-deprecated-active",
		Type:   model.ResourceTypeAlert,
		Name:   "DeprecatedActiveAlert",
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:deprecated-active"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			model.MetadataEndsAt:     now.Add(-time.Hour).Format(time.RFC3339),
		},
		Status: model.ResourceStatusDeprecated,
	}
	for _, resource := range []model.Resource{freshAlert, expiredAlert, suppressedAlert, prometheusAlert, deprecatedActiveAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewExpiredActiveAlertAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != expiredAlert.ID {
		t.Fatalf("expected expired active alert finding, got %s", findings[0].Resource.ID)
	}
	if findings[0].Metadata["expired_for"] == "" {
		t.Fatalf("expected expired_for metadata, got %#v", findings[0].Metadata)
	}
}

func TestExpiredActiveAlertAnalyzerConfig(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	alert := model.Resource{
		ID:     "alert-expired",
		Type:   model.ResourceTypeAlert,
		Name:   "ExpiredAlert",
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:expired"},
		Metadata: map[string]string{
			model.MetadataAlertState:  "active",
			model.MetadataFingerprint: "expired-fingerprint",
			model.MetadataEndsAt:      time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		},
		Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, alert); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewExpiredActiveAlertAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"expired_active_alert_grace": "2h",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding with larger grace, got %d", len(findings))
	}

	findings, err = NewExpiredActiveAlertAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"allowed_expired_active_alerts": "expired-fingerprint",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer with allowlist: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding for allowed alert, got %d", len(findings))
	}
}
