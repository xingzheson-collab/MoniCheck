package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorZeroReplicaCoverageAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	covered := kubernetesPrometheusCoverageTarget("covered", "1", "1")
	zeroOnly := kubernetesPrometheusCoverageTarget("zero-only", "2", "0")
	unselected := kubernetesPrometheusCoverageTarget("unselected", "0", "0")
	for _, resource := range []model.Resource{covered, zeroOnly, unselected} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesMonitorZeroReplicaCoverageAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != zeroOnly.ID || findings[0].Severity != model.SeverityCritical || findings[0].Category != model.FindingCategoryReliability {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestKubernetesPrometheusPausedAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	paused := kubernetesPrometheusResource("paused", "true")
	active := kubernetesPrometheusResource("active", "false")
	for _, resource := range []model.Resource{paused, active} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesPrometheusPausedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != paused.ID || findings[0].Severity != model.SeverityWarning {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestKubernetesPrometheusAgentWithoutRemoteWriteAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	missing := kubernetesPrometheusAgentResource("missing", "0")
	configured := kubernetesPrometheusAgentResource("configured", "1")
	for _, resource := range []model.Resource{missing, configured} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesPrometheusAgentWithoutRemoteWriteAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != missing.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestKubernetesPrometheusPausedAnalyzerIncludesAgent(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	agent := kubernetesPrometheusAgentResource("paused-agent", "1")
	agent.Metadata["prometheus_paused"] = "true"
	if err := store.Resources.Upsert(ctx, agent); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	findings, err := NewKubernetesPrometheusPausedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Metadata["kubernetes_kind"] != "PrometheusAgent" {
		t.Fatalf("unexpected findings: %#v, err=%v", findings, err)
	}
}

func kubernetesPrometheusCoverageTarget(name string, selected string, nonzero string) model.Resource {
	return model.Resource{
		ID: name, UID: name, Type: model.ResourceTypeTarget, Name: name, Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "kubernetes"},
		Metadata: map[string]string{
			"kubernetes_kind":                   "ServiceMonitor",
			"namespace":                         "prod",
			"prometheus_selection_candidate":    "true",
			"prometheus_selected_count":         selected,
			"prometheus_nonzero_selected_count": nonzero,
		},
	}
}

func kubernetesPrometheusResource(name string, paused string) model.Resource {
	return model.Resource{
		ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: name, Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "kubernetes"},
		Metadata: map[string]string{
			"kubernetes_kind":              "Prometheus",
			"namespace":                    "monitoring",
			"prometheus_paused":            paused,
			"prometheus_desired_pod_count": "1",
		},
	}
}

func kubernetesPrometheusAgentResource(name string, remoteWriteCount string) model.Resource {
	resource := kubernetesPrometheusResource(name, "false")
	resource.Metadata["kubernetes_kind"] = "PrometheusAgent"
	resource.Metadata["prometheus_remote_write_count"] = remoteWriteCount
	return resource
}
