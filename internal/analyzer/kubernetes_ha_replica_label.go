package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const KubernetesHAReplicaExternalLabelDisabledAnalyzerID = "builtin.kubernetes_ha_replica_external_label_disabled"

type KubernetesHAReplicaExternalLabelDisabledAnalyzer struct{}

func NewKubernetesHAReplicaExternalLabelDisabledAnalyzer() *KubernetesHAReplicaExternalLabelDisabledAnalyzer {
	return &KubernetesHAReplicaExternalLabelDisabledAnalyzer{}
}

func (a *KubernetesHAReplicaExternalLabelDisabledAnalyzer) ID() string {
	return KubernetesHAReplicaExternalLabelDisabledAnalyzerID
}
func (a *KubernetesHAReplicaExternalLabelDisabledAnalyzer) Name() string {
	return "Kubernetes HA Replica External Label Disabled"
}
func (a *KubernetesHAReplicaExternalLabelDisabledAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesHAReplicaExternalLabelDisabledAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesHAReplicaExternalLabelDisabledAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := strings.TrimSpace(resource.Metadata["kubernetes_kind"])
		replicas := kubernetesHAReplicaMetadataInt(resource, "prometheus_replicas")
		remoteWriteCount := kubernetesHAReplicaMetadataInt(resource, "prometheus_remote_write_count")
		objectStorage := resource.Metadata["prometheus_thanos_object_storage_declared"] == "true"
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_agent_mode"] == "daemonset" || replicas <= 1 || resource.Metadata["prometheus_replica_external_label_enabled"] != "false" || (remoteWriteCount == 0 && !objectStorage) {
			continue
		}
		exportModes := make([]string, 0, 2)
		if remoteWriteCount > 0 {
			exportModes = append(exportModes, fmt.Sprintf("%d remote-write destination(s)", remoteWriteCount))
		}
		if objectStorage {
			exportModes = append(exportModes, "Thanos object storage")
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "KubernetesHAReplicaExternalLabelDisabled",
			Severity:       model.SeverityWarning,
			Category:       model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("Kubernetes %s %q has %d replicas and exports through %s while replicaExternalLabelName is explicitly empty", kind, resource.Name, replicas, strings.Join(exportModes, " and "))},
			Recommendation: "配置非空 replicaExternalLabelName，并与远端系统的 HA 去重标签保持一致（例如 prometheus_replica 或 __replica__）；同时使用稳定 externalLabels 标识同一 HA 集群，验证远端不会把副本样本错误合并或重复计数。",
			Metadata: map[string]string{
				"analyzer_id":                    a.ID(),
				"kubernetes_kind":                kind,
				"namespace":                      kubernetesResourceNamespace(resource),
				"prometheus_replicas":            strconv.Itoa(replicas),
				"prometheus_remote_write_count":  strconv.Itoa(remoteWriteCount),
				"thanos_object_storage_declared": strconv.FormatBool(objectStorage),
			},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesHAReplicaMetadataInt(resource model.Resource, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(resource.Metadata[key]))
	if err != nil || value < 0 {
		return 0
	}
	return value
}
