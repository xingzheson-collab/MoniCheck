package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestAlertmanagerRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		alertmanagerRuntimeTestResource("settling", "settling", "1"),
		alertmanagerRuntimeTestResource("singleton", "ready", "1"),
		alertmanagerRuntimeTestResource("healthy", "ready", "3"),
		alertmanagerRuntimeTestResource("disabled", "disabled", "0"),
	}
	wrongSource := alertmanagerRuntimeTestResource("wrong-source", "settling", "1")
	wrongSource.Source.System = "kubernetes"
	deprecated := alertmanagerRuntimeTestResource("deprecated", "settling", "1")
	deprecated.Status = model.ResourceStatusDeprecated
	resources = append(resources, wrongSource, deprecated)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert runtime resource: %v", err)
		}
	}

	notReady, err := NewAlertmanagerClusterNotReadyAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute not-ready analyzer: %v", err)
	}
	if len(notReady) != 1 ||
		notReady[0].Resource.ID != "settling" ||
		notReady[0].Type != "AlertmanagerClusterNotReady" ||
		notReady[0].Metadata["cluster_status"] != "settling" ||
		notReady[0].Metadata["peer_count"] != "1" ||
		notReady[0].Category != model.FindingCategoryReliability ||
		model.DefaultFindingCategory(notReady[0].Type, notReady[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected Alertmanager not-ready findings: %#v", notReady)
	}

	singleton, err := NewAlertmanagerSingletonClusterAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute singleton analyzer: %v", err)
	}
	if len(singleton) != 1 ||
		singleton[0].Resource.ID != "singleton" ||
		singleton[0].Type != "AlertmanagerSingletonCluster" ||
		singleton[0].Metadata["peer_count"] != "1" ||
		singleton[0].Severity != model.SeverityWarning {
		t.Fatalf("unexpected Alertmanager singleton findings: %#v", singleton)
	}
}

func alertmanagerRuntimeTestResource(id, status, peerCount string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeInstance,
		Name:   "Alertmanager Runtime",
		Source: model.SourceInfo{System: "alertmanager", Instance: "http://" + id},
		Metadata: map[string]string{
			model.MetadataAlertmanagerRuntime:          "true",
			model.MetadataAlertmanagerClusterStatus:    status,
			model.MetadataAlertmanagerClusterPeerCount: peerCount,
		},
		Status: model.ResourceStatusActive,
	}
}
