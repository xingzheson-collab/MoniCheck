package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerTerminationAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := alertmanagerTerminationResource("valid", "true", "120", "false")
	immediate := alertmanagerTerminationResource("immediate", "true", "0", "false")
	invalid := alertmanagerTerminationResource("invalid", "false", "0", "false")
	unsupported := alertmanagerTerminationResource("unsupported", "true", "120", "true")
	for _, resource := range []model.Resource{valid, immediate, invalid, unsupported} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	for _, test := range []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerTerminationGraceAnalyzer(), invalid.ID},
		{NewKubernetesImmediateAlertmanagerTerminationAnalyzer(), immediate.ID},
		{NewKubernetesUnsupportedAlertmanagerTerminationGraceVersionAnalyzer(), unsupported.ID},
	} {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != model.SeverityCritical {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerTerminationResource(name, valid, seconds, unsupported string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_version": "v0.24.0", "alertmanager_termination_grace_declared": "true", "alertmanager_termination_grace_valid": valid, "alertmanager_termination_grace_seconds": seconds, "alertmanager_termination_grace_version_unsupported": unsupported}}
}
