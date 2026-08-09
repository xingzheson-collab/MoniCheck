package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestSuppressedAlertAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	activeAlert := model.Resource{
		ID:     "alert-active",
		Type:   model.ResourceTypeAlert,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:active"},
		Metadata: map[string]string{
			model.MetadataAlertState: "firing",
		},
	}
	suppressedAlert := model.Resource{
		ID:     "alert-suppressed",
		Type:   model.ResourceTypeAlert,
		Name:   "LegacyAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:suppressed"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			model.MetadataSilencedBy: "silence-1",
		},
	}
	resolvedSuppressedAlert := model.Resource{
		ID:     "alert-resolved-suppressed",
		Type:   model.ResourceTypeAlert,
		Name:   "ResolvedLegacyAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:resolved-suppressed"},
		Metadata: map[string]string{
			model.MetadataAlertState: "resolved",
			model.MetadataSilencedBy: "silence-2",
		},
	}
	prometheusSuppressedAlert := model.Resource{
		ID:     "alert-prom-suppressed",
		Type:   model.ResourceTypeAlert,
		Name:   "PrometheusAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "alert:prom-suppressed"},
		Metadata: map[string]string{
			model.MetadataAlertState: "firing",
			model.MetadataSilencedBy: "silence-3",
		},
	}
	deprecatedSuppressedAlert := model.Resource{
		ID:     "alert-deprecated-suppressed",
		Type:   model.ResourceTypeAlert,
		Name:   "DeprecatedSuppressedAlert",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:deprecated-suppressed"},
		Metadata: map[string]string{
			model.MetadataAlertState: "firing",
			model.MetadataSilencedBy: "silence-4",
		},
	}

	for _, resource := range []model.Resource{activeAlert, suppressedAlert, resolvedSuppressedAlert, prometheusSuppressedAlert, deprecatedSuppressedAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewSuppressedAlertAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != suppressedAlert.ID {
		t.Fatalf("expected suppressed alert finding for %s, got %s", suppressedAlert.ID, findings[0].Resource.ID)
	}
}
