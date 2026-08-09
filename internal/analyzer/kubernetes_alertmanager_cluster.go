package analyzer

import (
	"context"
	"fmt"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesInvalidAlertmanagerClusterConfigurationAnalyzerID  = "builtin.kubernetes_invalid_alertmanager_cluster_configuration"
	KubernetesAlertmanagerExternalPeersClusterDisabledAnalyzerID = "builtin.kubernetes_alertmanager_external_peers_cluster_disabled"
	KubernetesAlertmanagerExternalPeersWithoutLabelAnalyzerID    = "builtin.kubernetes_alertmanager_external_peers_without_label"
	KubernetesAlertmanagerUnreachableAdvertiseAddressAnalyzerID  = "builtin.kubernetes_alertmanager_unreachable_cluster_advertise_address"
)

type KubernetesAlertmanagerClusterAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerClusterConfigurationAnalyzer() *KubernetesAlertmanagerClusterAnalyzer {
	return &KubernetesAlertmanagerClusterAnalyzer{id: KubernetesInvalidAlertmanagerClusterConfigurationAnalyzerID, name: "Kubernetes Invalid Alertmanager Cluster Configuration"}
}

func NewKubernetesAlertmanagerExternalPeersClusterDisabledAnalyzer() *KubernetesAlertmanagerClusterAnalyzer {
	return &KubernetesAlertmanagerClusterAnalyzer{id: KubernetesAlertmanagerExternalPeersClusterDisabledAnalyzerID, name: "Kubernetes Alertmanager External Peers With Cluster Mode Disabled"}
}

func NewKubernetesAlertmanagerExternalPeersWithoutLabelAnalyzer() *KubernetesAlertmanagerClusterAnalyzer {
	return &KubernetesAlertmanagerClusterAnalyzer{id: KubernetesAlertmanagerExternalPeersWithoutLabelAnalyzerID, name: "Kubernetes Alertmanager External Peers Without Cluster Label"}
}

func NewKubernetesAlertmanagerUnreachableAdvertiseAddressAnalyzer() *KubernetesAlertmanagerClusterAnalyzer {
	return &KubernetesAlertmanagerClusterAnalyzer{id: KubernetesAlertmanagerUnreachableAdvertiseAddressAnalyzerID, name: "Kubernetes Alertmanager Unreachable Cluster Advertise Address"}
}

func (a *KubernetesAlertmanagerClusterAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerClusterAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerClusterAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerClusterAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerClusterAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_cluster_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerClusterFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerClusterFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	peerCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_additional_peer_count")
	invalidPeerCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_additional_peer_invalid_count")
	duplicatePeerCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_additional_peer_duplicate_count")
	invalidTimingCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_cluster_timing_invalid_count")
	switch analyzerID {
	case KubernetesInvalidAlertmanagerClusterConfigurationAnalyzerID:
		invalidForceMode := resource.Metadata["alertmanager_force_cluster_mode_declared"] == "true" && resource.Metadata["alertmanager_force_cluster_mode_valid"] != "true"
		invalidClusterLabel := resource.Metadata["alertmanager_cluster_label_invalid"] == "true"
		invalidAdvertiseAddress := resource.Metadata["alertmanager_cluster_advertise_address_declared"] == "true" && resource.Metadata["alertmanager_cluster_advertise_address_valid"] != "true"
		if invalidPeerCount == 0 && duplicatePeerCount == 0 && invalidTimingCount == 0 && !invalidForceMode && !invalidClusterLabel && !invalidAdvertiseAddress {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidAlertmanagerClusterConfiguration"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has invalid HA cluster settings: malformed peers=%d, duplicate peers=%d, invalid timings=%d, invalid advertise address=%t", resource.Name, invalidPeerCount, duplicatePeerCount, invalidTimingCount, invalidAdvertiseAddress)
		recommendation = "将 additionalPeers 和 clusterAdvertiseAddress 配置为可解析的 host:port，使用唯一 peer、正 Go duration 和布尔 forceEnableClusterMode。"
		metadata["alertmanager_additional_peer_invalid_count"] = fmt.Sprintf("%d", invalidPeerCount)
		metadata["alertmanager_additional_peer_duplicate_count"] = fmt.Sprintf("%d", duplicatePeerCount)
		metadata["alertmanager_cluster_timing_invalid_count"] = fmt.Sprintf("%d", invalidTimingCount)
		metadata["alertmanager_cluster_advertise_address_invalid"] = fmt.Sprintf("%t", invalidAdvertiseAddress)
	case KubernetesAlertmanagerExternalPeersClusterDisabledAnalyzerID:
		if peerCount == 0 || invalidPeerCount > 0 || duplicatePeerCount > 0 || alertmanagerStorageMetadataInt64(resource, "alertmanager_replicas") > 1 || resource.Metadata["alertmanager_force_cluster_mode_enabled"] == "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesAlertmanagerExternalPeersClusterDisabled"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has one replica and %d external peer(s), but cluster mode is not forced on", resource.Name, peerCount)
		recommendation = "为跨 Kubernetes 集群的单副本 Alertmanager 设置 forceEnableClusterMode=true，并验证 TCP/UDP gossip 端口和成员状态。"
		metadata["alertmanager_additional_peer_count"] = fmt.Sprintf("%d", peerCount)
	case KubernetesAlertmanagerExternalPeersWithoutLabelAnalyzerID:
		if peerCount == 0 || invalidPeerCount > 0 || duplicatePeerCount > 0 || resource.Metadata["alertmanager_cluster_label_declared"] == "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		category = model.FindingCategoryReliability
		findingType = "KubernetesAlertmanagerExternalPeersWithoutLabel"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q connects to %d external peer(s) without an explicit cluster label", resource.Name, peerCount)
		recommendation = "为跨 Alertmanager resource 或跨 Kubernetes 集群的成员配置一致且唯一的 clusterLabel，避免错误加入其他集群。"
		metadata["alertmanager_additional_peer_count"] = fmt.Sprintf("%d", peerCount)
	case KubernetesAlertmanagerUnreachableAdvertiseAddressAnalyzerID:
		clusterEnabled := alertmanagerStorageMetadataInt64(resource, "alertmanager_replicas") > 1 || resource.Metadata["alertmanager_force_cluster_mode_enabled"] == "true"
		loopback := resource.Metadata["alertmanager_cluster_advertise_address_loopback"] == "true"
		unspecified := resource.Metadata["alertmanager_cluster_advertise_address_unspecified"] == "true"
		if !clusterEnabled || resource.Metadata["alertmanager_cluster_advertise_address_valid"] != "true" || (!loopback && !unspecified) {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesAlertmanagerUnreachableClusterAdvertiseAddress"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q enables HA clustering but advertises a %s address that other members cannot reach", resource.Name, alertmanagerAdvertiseAddressScope(loopback))
		recommendation = "将 clusterAdvertiseAddress 配置为其他 Alertmanager 成员可达的显式 host:port，并验证 gossip 端口的 TCP 和 UDP 连通性。"
		metadata["alertmanager_cluster_advertise_address_scope"] = alertmanagerAdvertiseAddressScope(loopback)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}

func alertmanagerAdvertiseAddressScope(loopback bool) string {
	if loopback {
		return "loopback"
	}
	return "unspecified"
}
