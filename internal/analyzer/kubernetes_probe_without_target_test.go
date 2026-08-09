package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesProbeWithoutTargetAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	staticTargets := kubernetesProbeResource("probe-static", "static", "static", "2", "blackbox:9115")
	ingressTargets := kubernetesProbeResource("probe-ingress", "ingress", "ingress", "0", "blackbox:9115")
	emptyStatic := kubernetesProbeResource("probe-empty", "empty", "static", "0", "blackbox:9115")
	missingTargets := kubernetesProbeResource("probe-missing", "missing", "", "0", "blackbox:9115")
	serviceMonitor := kubernetesMonitorResource("monitor", "api-monitor", "prod", "ServiceMonitor")

	for _, resource := range []model.Resource{staticTargets, ingressTargets, emptyStatic, missingTargets, serviceMonitor} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesProbeWithoutTargetAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		if finding.Severity != model.SeverityCritical || finding.Category != model.FindingCategoryConfiguration {
			t.Fatalf("unexpected finding: %#v", finding)
		}
	}
	if !found[emptyStatic.ID] || !found[missingTargets.ID] || found[staticTargets.ID] || found[ingressTargets.ID] {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func kubernetesProbeResource(id string, name string, mode string, count string, proberURL string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTarget,
		Name:   name,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "kubernetes", Instance: "/etc/kubernetes", ExternalID: "probe:prod/" + name},
		Metadata: map[string]string{
			"kubernetes_kind":    "Probe",
			"namespace":          "prod",
			"probe_target_mode":  mode,
			"probe_target_count": count,
			"probe_prober_url":   proberURL,
		},
	}
}
