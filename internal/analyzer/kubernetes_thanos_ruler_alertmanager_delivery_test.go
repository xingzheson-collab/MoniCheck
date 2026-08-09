package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerAlertmanagerDeliveryAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerAlertmanagerDeliveryResource("invalid")
	invalid.Metadata["thanos_ruler_alertmanager_url_invalid_count"] = "2"
	invalid.Metadata["thanos_ruler_alertmanager_url_duplicate_count"] = "1"
	missing := thanosRulerAlertmanagerDeliveryResource("missing")
	missing.Metadata["thanos_ruler_selected_alert_rule_count"] = "3"
	plaintext := thanosRulerAlertmanagerDeliveryResource("plaintext")
	plaintext.Metadata["thanos_ruler_plaintext_alertmanager_url_count"] = "1"
	unsupported := thanosRulerAlertmanagerDeliveryResource("unsupported")
	unsupported.Metadata["thanos_ruler_alertmanager_config_version_unsupported"] = "true"
	for _, resource := range []model.Resource{invalid, missing, plaintext, unsupported} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		category model.FindingCategory
	}{
		{NewKubernetesInvalidThanosRulerAlertmanagerURLsAnalyzer(), invalid.ID, model.FindingCategoryConfiguration},
		{NewKubernetesThanosRulerAlertingWithoutAlertmanagerAnalyzer(), missing.ID, model.FindingCategoryReliability},
		{NewKubernetesPlaintextThanosRulerAlertmanagerAnalyzer(), plaintext.ID, model.FindingCategorySecurity},
		{NewKubernetesUnsupportedThanosRulerAlertmanagerConfigAnalyzer(), unsupported.ID, model.FindingCategoryConfiguration},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Category != test.category {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func TestKubernetesThanosRulerAlertingWithoutAlertmanagerSuppressesRecordingOnly(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := thanosRulerAlertmanagerDeliveryResource("recording-only")
	resource.Metadata["thanos_ruler_selected_rule_count"] = "4"
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	findings, err := NewKubernetesThanosRulerAlertingWithoutAlertmanagerAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected recording-only suppression, got %#v err=%v", findings, err)
	}
}

func thanosRulerAlertmanagerDeliveryResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{
		"kubernetes_kind":      "ThanosRuler",
		"namespace":            "monitoring",
		"thanos_ruler_version": "v0.9.0",
		"thanos_ruler_alertmanager_delivery_metadata":          "true",
		"thanos_ruler_alertmanager_url_invalid_count":          "0",
		"thanos_ruler_alertmanager_url_duplicate_count":        "0",
		"thanos_ruler_plaintext_alertmanager_url_count":        "0",
		"thanos_ruler_alertmanager_delivery_configured":        "false",
		"thanos_ruler_alertmanager_config_version_unsupported": "false",
		"thanos_ruler_selected_rule_count":                     "0",
		"thanos_ruler_selected_alert_rule_count":               "0",
	}}
}
