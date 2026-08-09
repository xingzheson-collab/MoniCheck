package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBlackholeReceiverAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	normalAlert := model.Resource{
		ID:     "normal-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:normal"},
		Metadata: map[string]string{
			model.MetadataAlertState:    "active",
			model.MetadataReceiverNames: "pagerduty,slack-platform",
		},
	}
	blackholeAlert := model.Resource{
		ID:     "blackhole-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "DBDown",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:blackhole"},
		Metadata: map[string]string{
			model.MetadataAlertState:    "active",
			model.MetadataReceiverNames: "pagerduty,blackhole",
		},
	}
	suppressedAlert := model.Resource{
		ID:     "suppressed-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "SuppressedAlert",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:suppressed"},
		Metadata: map[string]string{
			model.MetadataAlertState:    "suppressed",
			model.MetadataReceiverNames: "blackhole",
		},
	}
	deprecatedActiveAlert := model.Resource{
		ID:     "deprecated-active-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "DeprecatedActiveAlert",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:deprecated-active"},
		Metadata: map[string]string{
			model.MetadataAlertState:    "active",
			model.MetadataReceiverNames: "blackhole",
		},
	}
	prometheusAlert := model.Resource{
		ID:     "prometheus-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "PrometheusAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "alert:prometheus"},
		Metadata: map[string]string{
			model.MetadataAlertState:    "active",
			model.MetadataReceiverNames: "blackhole",
		},
	}
	for _, resource := range []model.Resource{normalAlert, blackholeAlert, suppressedAlert, deprecatedActiveAlert, prometheusAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewBlackholeReceiverAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != blackholeAlert.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected critical blackhole receiver finding, got %#v", findings[0])
	}
	if findings[0].Metadata["receivers"] != "blackhole" {
		t.Fatalf("expected receiver metadata, got %#v", findings[0].Metadata)
	}
}

func TestBlackholeReceiverAnalyzerConfiguredNames(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	alert := model.Resource{
		ID:     "alert",
		Type:   model.ResourceTypeAlert,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:configured"},
		Metadata: map[string]string{
			model.MetadataAlertState:    "active",
			model.MetadataReceiverNames: "testing",
		},
	}
	if err := store.Resources.Upsert(ctx, alert); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewBlackholeReceiverAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"blackhole_receiver_names": "testing",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected configured blackhole receiver finding, got %d", len(findings))
	}
}

func TestBlackholeReceiverAnalyzerConfiguredReceiver(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	receiver := model.Resource{
		ID:     "receiver-blackhole",
		Type:   model.ResourceTypeReceiver,
		Name:   "blackhole",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:blackhole"},
		Metadata: map[string]string{
			"receiver_name":       "blackhole",
			"referenced_by_route": "true",
		},
	}
	unusedReceiver := model.Resource{
		ID:     "receiver-unused",
		Type:   model.ResourceTypeReceiver,
		Name:   "drop",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:drop"},
		Metadata: map[string]string{
			"receiver_name": "drop",
		},
	}
	deprecatedReceiver := model.Resource{
		ID:     "receiver-deprecated",
		Type:   model.ResourceTypeReceiver,
		Name:   "null",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:null"},
		Metadata: map[string]string{
			"receiver_name":       "null",
			"referenced_by_route": "true",
		},
	}
	for _, resource := range []model.Resource{receiver, unusedReceiver, deprecatedReceiver} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewBlackholeReceiverAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected configured receiver finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != receiver.ID || findings[0].Resource.Type != model.ResourceTypeReceiver {
		t.Fatalf("expected receiver finding, got %#v", findings[0])
	}
}
