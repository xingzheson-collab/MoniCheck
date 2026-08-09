package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerPresentationAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerPresentationResource("invalid")
	invalid.Metadata["thanos_ruler_presentation_invalid_setting_count"] = "2"
	plaintext := thanosRulerPresentationResource("plaintext")
	plaintext.Metadata["thanos_ruler_alert_query_url_valid"] = "true"
	plaintext.Metadata["thanos_ruler_alert_query_url_scheme"] = "http"
	override := thanosRulerPresentationResource("override")
	override.Metadata["thanos_ruler_replica_label_override"] = "true"
	dropped := thanosRulerPresentationResource("dropped")
	dropped.Metadata["thanos_ruler_dropped_external_label_count"] = "2"
	isolation := thanosRulerPresentationResource("isolation")
	isolation.Metadata["thanos_ruler_host_users_valid"] = "true"
	isolation.Metadata["thanos_ruler_user_namespace_isolation_enabled"] = "true"
	for _, resource := range []model.Resource{invalid, plaintext, override, dropped, isolation} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		category model.FindingCategory
	}{
		{NewKubernetesInvalidThanosRulerPresentationAnalyzer(), invalid.ID, model.FindingCategoryConfiguration},
		{NewKubernetesPlaintextThanosRulerAlertQueryAnalyzer(), plaintext.ID, model.FindingCategorySecurity},
		{NewKubernetesThanosRulerReplicaLabelOverrideAnalyzer(), override.ID, model.FindingCategoryConfiguration},
		{NewKubernetesThanosRulerDroppedExternalLabelsAnalyzer(), dropped.ID, model.FindingCategoryReliability},
		{NewKubernetesThanosRulerUserNamespaceIsolationAnalyzer(), isolation.ID, model.FindingCategoryConfiguration},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Category != test.category {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func TestKubernetesPlaintextThanosRulerAlertQuerySuppressesLoopback(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := thanosRulerPresentationResource("loopback")
	resource.Metadata["thanos_ruler_alert_query_url_valid"] = "true"
	resource.Metadata["thanos_ruler_alert_query_url_scheme"] = "http"
	resource.Metadata["thanos_ruler_alert_query_url_loopback"] = "true"
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	findings, err := NewKubernetesPlaintextThanosRulerAlertQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected loopback suppression, got %#v err=%v", findings, err)
	}
}

func thanosRulerPresentationResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{
		"kubernetes_kind":                    "ThanosRuler",
		"namespace":                          "monitoring",
		"thanos_ruler_presentation_metadata": "true",
		"thanos_ruler_presentation_invalid_setting_count": "0",
		"thanos_ruler_alert_query_url_valid":              "false",
		"thanos_ruler_alert_query_url_scheme":             "",
		"thanos_ruler_alert_query_url_loopback":           "false",
		"thanos_ruler_replica_label_override":             "false",
		"thanos_ruler_dropped_external_label_count":       "0",
		"thanos_ruler_host_users_valid":                   "false",
		"thanos_ruler_user_namespace_isolation_enabled":   "false",
	}}
}
