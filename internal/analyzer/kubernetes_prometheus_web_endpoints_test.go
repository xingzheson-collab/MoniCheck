package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusWebEndpointAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		kubernetesPrometheusWebResource("server-risk", "Prometheus", "true", "true", "true"),
		kubernetesPrometheusWebResource("server-safe", "Prometheus", "false", "false", "false"),
		kubernetesPrometheusWebResource("agent-receiver", "PrometheusAgent", "false", "true", "true"),
		kubernetesPrometheusWebResource("agent-admin-ignored", "PrometheusAgent", "true", "false", "false"),
		kubernetesPrometheusWebResource("other-source", "Prometheus", "true", "true", "true"),
		kubernetesPrometheusWebResource("deprecated", "Prometheus", "true", "true", "true"),
	}
	resources[4].Source.System = "sample"
	resources[5].Status = model.ResourceStatusDeprecated
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	adminFindings, err := NewKubernetesPrometheusAdminAPIEnabledAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute admin API analyzer: %v", err)
	}
	if len(adminFindings) != 1 || adminFindings[0].Resource.ID != "server-risk" || adminFindings[0].Severity != model.SeverityCritical || adminFindings[0].Category != model.FindingCategorySecurity {
		t.Fatalf("unexpected admin API findings: %#v", adminFindings)
	}

	receiverFindings, err := NewKubernetesRemoteWriteReceiverEnabledAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute remote write receiver analyzer: %v", err)
	}
	if len(receiverFindings) != 2 || receiverFindings[0].Resource.ID != "agent-receiver" || receiverFindings[1].Resource.ID != "server-risk" {
		t.Fatalf("unexpected remote write receiver findings: %#v", receiverFindings)
	}
	for _, finding := range receiverFindings {
		if finding.Severity != model.SeverityWarning || finding.Category != model.FindingCategoryConfiguration {
			t.Fatalf("unexpected receiver finding classification: %#v", finding)
		}
	}

	otlpFindings, err := NewKubernetesOTLPReceiverEnabledAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute OTLP receiver analyzer: %v", err)
	}
	if len(otlpFindings) != 2 || otlpFindings[0].Resource.ID != "agent-receiver" || otlpFindings[1].Resource.ID != "server-risk" {
		t.Fatalf("unexpected OTLP receiver findings: %#v", otlpFindings)
	}
}

func TestKubernetesUnsupportedReceiverVersionAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	oldBoth := kubernetesPrometheusWebResource("old-both", "Prometheus", "false", "true", "true")
	oldBoth.Metadata["prometheus_version"] = "v2.32.1"
	oldBoth.Metadata["prometheus_remote_write_receiver_version_unsupported"] = "true"
	oldBoth.Metadata["prometheus_otlp_receiver_version_unsupported"] = "true"
	oldOTLP := kubernetesPrometheusWebResource("old-otlp", "PrometheusAgent", "false", "false", "true")
	oldOTLP.Metadata["prometheus_version"] = "2.46.0"
	oldOTLP.Metadata["prometheus_otlp_receiver_version_unsupported"] = "true"
	supported := kubernetesPrometheusWebResource("supported", "Prometheus", "false", "true", "true")
	supported.Metadata["prometheus_version"] = "v2.47.0"
	unknown := kubernetesPrometheusWebResource("unknown", "Prometheus", "false", "true", "true")
	for _, resource := range []model.Resource{oldBoth, oldOTLP, supported, unknown} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesUnsupportedReceiverVersionAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute unsupported receiver version analyzer: %v", err)
	}
	if len(findings) != 2 || findings[0].Resource.ID != "old-both" || findings[1].Resource.ID != "old-otlp" {
		t.Fatalf("unexpected receiver version findings: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Severity != model.SeverityCritical || finding.Category != model.FindingCategoryReliability {
			t.Fatalf("unexpected version finding classification: %#v", finding)
		}
	}
}

func kubernetesPrometheusWebResource(id string, kind string, adminEnabled string, receiverEnabled string, otlpEnabled string) model.Resource {
	return model.Resource{
		ID: id, UID: id, Type: model.ResourceTypeTSDB, Name: "monitoring/" + id,
		Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			"kubernetes_kind": kind, "namespace": "monitoring",
			"prometheus_admin_api_enabled":             adminEnabled,
			"prometheus_remote_write_receiver_enabled": receiverEnabled,
			"prometheus_otlp_receiver_enabled":         otlpEnabled,
		},
	}
}
