package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesHAReplicaExternalLabelDisabledAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	remoteRisk := kubernetesHAReplicaResource("remote-risk", "Prometheus", "2", "false", "1", "false")
	thanosRisk := kubernetesHAReplicaResource("thanos-risk", "Prometheus", "3", "false", "0", "true")
	defaultLabel := kubernetesHAReplicaResource("default-label", "Prometheus", "2", "true", "1", "false")
	single := kubernetesHAReplicaResource("single", "Prometheus", "1", "false", "1", "false")
	localOnly := kubernetesHAReplicaResource("local-only", "Prometheus", "2", "false", "0", "false")
	daemonAgent := kubernetesHAReplicaResource("daemon-agent", "PrometheusAgent", "3", "false", "1", "false")
	daemonAgent.Metadata["prometheus_agent_mode"] = "daemonset"
	for _, resource := range []model.Resource{remoteRisk, thanosRisk, defaultLabel, single, localOnly, daemonAgent} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesHAReplicaExternalLabelDisabledAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected remote-write and Thanos risks, got %#v", findings)
	}
	for _, finding := range findings {
		if finding.Category != model.FindingCategoryReliability || finding.Severity != model.SeverityWarning {
			t.Fatalf("unexpected finding classification: %#v", finding)
		}
	}
}

func kubernetesHAReplicaResource(id string, kind string, replicas string, labelEnabled string, remoteWriteCount string, objectStorage string) model.Resource {
	return model.Resource{
		ID: id, UID: id, Type: model.ResourceTypeTSDB, Name: "monitoring/" + id,
		Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			"kubernetes_kind":     kind,
			"namespace":           "monitoring",
			"prometheus_replicas": replicas,
			"prometheus_replica_external_label_enabled": labelEnabled,
			"prometheus_remote_write_count":             remoteWriteCount,
			"prometheus_thanos_object_storage_declared": objectStorage,
		},
	}
}
