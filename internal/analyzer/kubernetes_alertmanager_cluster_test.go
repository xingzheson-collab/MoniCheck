package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerClusterAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := alertmanagerClusterResource("valid")
	invalid := alertmanagerClusterResource("invalid")
	invalid.Metadata["alertmanager_additional_peer_invalid_count"] = "1"
	disabled := alertmanagerClusterResource("disabled")
	disabled.Metadata["alertmanager_force_cluster_mode_enabled"] = "false"
	unlabeled := alertmanagerClusterResource("unlabeled")
	unlabeled.Metadata["alertmanager_cluster_label_declared"] = "false"
	unreachable := alertmanagerClusterResource("unreachable")
	unreachable.Metadata["alertmanager_replicas"] = "2"
	unreachable.Metadata["alertmanager_cluster_advertise_address_declared"] = "true"
	unreachable.Metadata["alertmanager_cluster_advertise_address_valid"] = "true"
	unreachable.Metadata["alertmanager_cluster_advertise_address_loopback"] = "true"
	for _, resource := range []model.Resource{valid, invalid, disabled, unlabeled, unreachable} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidAlertmanagerClusterConfigurationAnalyzer(), invalid.ID, model.SeverityCritical},
		{NewKubernetesAlertmanagerExternalPeersClusterDisabledAnalyzer(), disabled.ID, model.SeverityCritical},
		{NewKubernetesAlertmanagerExternalPeersWithoutLabelAnalyzer(), unlabeled.ID, model.SeverityWarning},
		{NewKubernetesAlertmanagerUnreachableAdvertiseAddressAnalyzer(), unreachable.ID, model.SeverityCritical},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerClusterResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_cluster_metadata": "true", "alertmanager_replicas": "1", "alertmanager_additional_peer_count": "1", "alertmanager_additional_peer_invalid_count": "0", "alertmanager_additional_peer_duplicate_count": "0", "alertmanager_cluster_timing_invalid_count": "0", "alertmanager_force_cluster_mode_declared": "true", "alertmanager_force_cluster_mode_valid": "true", "alertmanager_force_cluster_mode_enabled": "true", "alertmanager_cluster_label_declared": "true", "alertmanager_cluster_label_valid": "true", "alertmanager_cluster_label_invalid": "false", "alertmanager_cluster_advertise_address_declared": "false", "alertmanager_cluster_advertise_address_valid": "false", "alertmanager_cluster_advertise_address_loopback": "false", "alertmanager_cluster_advertise_address_unspecified": "false"}}
}

func TestKubernetesAlertmanagerUnreachableAdvertiseAddressBoundaries(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name     string
		replicas string
		forced   string
		valid    string
		loopback string
		wildcard string
		expected bool
	}{
		{name: "HA loopback", replicas: "2", valid: "true", loopback: "true", expected: true},
		{name: "forced wildcard", replicas: "1", forced: "true", valid: "true", wildcard: "true", expected: true},
		{name: "single replica inert", replicas: "1", valid: "true", loopback: "true"},
		{name: "routable", replicas: "3", valid: "true"},
		{name: "malformed handled separately", replicas: "3", loopback: "true"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := alertmanagerClusterResource(test.name)
			resource.Metadata["alertmanager_replicas"] = test.replicas
			resource.Metadata["alertmanager_force_cluster_mode_enabled"] = test.forced
			resource.Metadata["alertmanager_cluster_advertise_address_valid"] = test.valid
			resource.Metadata["alertmanager_cluster_advertise_address_loopback"] = test.loopback
			resource.Metadata["alertmanager_cluster_advertise_address_unspecified"] = test.wildcard
			_, matched := kubernetesAlertmanagerClusterFinding(KubernetesAlertmanagerUnreachableAdvertiseAddressAnalyzerID, resource, now)
			if matched != test.expected {
				t.Fatalf("expected matched=%t, got %t", test.expected, matched)
			}
		})
	}
}
