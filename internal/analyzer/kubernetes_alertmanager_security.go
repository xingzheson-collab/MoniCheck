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
	KubernetesAlertmanagerHostNetworkAnalyzerID                  = "builtin.kubernetes_alertmanager_host_network"
	KubernetesAlertmanagerAutomountTokenAnalyzerID               = "builtin.kubernetes_alertmanager_automount_service_account_token"
	KubernetesAlertmanagerHAWithoutClusterTLSAnalyzerID          = "builtin.kubernetes_alertmanager_ha_without_cluster_tls"
	KubernetesInvalidAlertmanagerSecurityAnalyzerID              = "builtin.kubernetes_invalid_alertmanager_security_configuration"
	KubernetesUnsupportedAlertmanagerClusterTLSVersionAnalyzerID = "builtin.kubernetes_unsupported_alertmanager_cluster_tls_version"
)

type KubernetesAlertmanagerSecurityAnalyzer struct {
	id   string
	name string
}

func NewKubernetesAlertmanagerHostNetworkAnalyzer() *KubernetesAlertmanagerSecurityAnalyzer {
	return &KubernetesAlertmanagerSecurityAnalyzer{id: KubernetesAlertmanagerHostNetworkAnalyzerID, name: "Kubernetes Alertmanager Host Network"}
}
func NewKubernetesAlertmanagerAutomountTokenAnalyzer() *KubernetesAlertmanagerSecurityAnalyzer {
	return &KubernetesAlertmanagerSecurityAnalyzer{id: KubernetesAlertmanagerAutomountTokenAnalyzerID, name: "Kubernetes Alertmanager Automount Service Account Token"}
}
func NewKubernetesAlertmanagerHAWithoutClusterTLSAnalyzer() *KubernetesAlertmanagerSecurityAnalyzer {
	return &KubernetesAlertmanagerSecurityAnalyzer{id: KubernetesAlertmanagerHAWithoutClusterTLSAnalyzerID, name: "Kubernetes Alertmanager HA Without Cluster TLS"}
}
func NewKubernetesInvalidAlertmanagerSecurityAnalyzer() *KubernetesAlertmanagerSecurityAnalyzer {
	return &KubernetesAlertmanagerSecurityAnalyzer{id: KubernetesInvalidAlertmanagerSecurityAnalyzerID, name: "Kubernetes Invalid Alertmanager Security Configuration"}
}
func NewKubernetesUnsupportedAlertmanagerClusterTLSVersionAnalyzer() *KubernetesAlertmanagerSecurityAnalyzer {
	return &KubernetesAlertmanagerSecurityAnalyzer{id: KubernetesUnsupportedAlertmanagerClusterTLSVersionAnalyzerID, name: "Kubernetes Unsupported Alertmanager Cluster TLS Version"}
}
func (a *KubernetesAlertmanagerSecurityAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerSecurityAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerSecurityAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerSecurityAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerSecurityAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_security_metadata"] != "true" {
			continue
		}
		finding, matched := kubernetesAlertmanagerSecurityFinding(a.id, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerSecurityFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityWarning
	category := model.FindingCategorySecurity
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesAlertmanagerHostNetworkAnalyzerID:
		if resource.Metadata["alertmanager_host_network_enabled"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerHostNetwork"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q uses the node network namespace", resource.Name)
		recommendation = "关闭 hostNetwork，使用 ClusterIP/Ingress 和 NetworkPolicy 暴露所需端口；确需主机网络时限制节点、端口和入站来源。"
	case KubernetesAlertmanagerAutomountTokenAnalyzerID:
		if resource.Metadata["alertmanager_automount_token_declared"] != "true" || resource.Metadata["alertmanager_automount_token_valid"] != "true" || resource.Metadata["alertmanager_automount_token_enabled"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerAutomountServiceAccountToken"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q explicitly mounts a ServiceAccount API token", resource.Name)
		recommendation = "若 Alertmanager 不需要访问 Kubernetes API，设置 automountServiceAccountToken=false，并最小化 ServiceAccount RBAC 权限。"
	case KubernetesAlertmanagerHAWithoutClusterTLSAnalyzerID:
		replicas := alertmanagerStorageMetadataInt64(resource, "alertmanager_replicas")
		if replicas <= 1 || resource.Metadata["alertmanager_cluster_tls_declared"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerHAWithoutClusterTLS"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q runs %d replicas without declared clusterTLS for gossip traffic", resource.Name, replicas)
		recommendation = "为 HA Alertmanager 配置 clusterTLS.server 和 clusterTLS.client 双向 TLS，并通过 NetworkPolicy 限制 gossip 端口。"
		metadata["alertmanager_replicas"] = fmt.Sprintf("%d", replicas)
	case KubernetesInvalidAlertmanagerSecurityAnalyzerID:
		invalidHost := resource.Metadata["alertmanager_host_network_declared"] == "true" && resource.Metadata["alertmanager_host_network_valid"] != "true"
		invalidToken := resource.Metadata["alertmanager_automount_token_declared"] == "true" && resource.Metadata["alertmanager_automount_token_valid"] != "true"
		invalidTLS := alertmanagerStorageMetadataInt64(resource, "alertmanager_cluster_tls_invalid_setting_count")
		if !invalidHost && !invalidToken && invalidTLS == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidAlertmanagerSecurityConfiguration"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has malformed network booleans or %d incomplete clusterTLS side(s)", resource.Name, invalidTLS)
		recommendation = "使用布尔值配置 hostNetwork/automountServiceAccountToken；clusterTLS 必须同时声明对象形式的 server 和 client 配置。"
	case KubernetesUnsupportedAlertmanagerClusterTLSVersionAnalyzerID:
		if resource.Metadata["alertmanager_cluster_tls_version_unsupported"] != "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryReliability
		findingType = "KubernetesUnsupportedAlertmanagerClusterTLSVersion"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares version %q with clusterTLS, which requires Alertmanager 0.24 or newer", resource.Name, resource.Metadata["alertmanager_version"])
		recommendation = "升级 Alertmanager 到 0.24 或更高版本，或移除不受支持的 clusterTLS 字段，并确认集群成员正常建立连接。"
		metadata["alertmanager_version"] = resource.Metadata["alertmanager_version"]
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
