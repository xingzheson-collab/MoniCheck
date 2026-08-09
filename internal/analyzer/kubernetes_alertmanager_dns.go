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
	KubernetesInvalidAlertmanagerDNSAnalyzerID            = "builtin.kubernetes_invalid_alertmanager_dns"
	KubernetesHostNetworkAlertmanagerClusterDNSFallbackID = "builtin.kubernetes_host_network_alertmanager_cluster_dns_fallback"
	KubernetesAlertmanagerServiceLinksEnabledAnalyzerID   = "builtin.kubernetes_alertmanager_service_links_enabled"
)

type KubernetesAlertmanagerDNSAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerDNSAnalyzer() *KubernetesAlertmanagerDNSAnalyzer {
	return &KubernetesAlertmanagerDNSAnalyzer{id: KubernetesInvalidAlertmanagerDNSAnalyzerID, name: "Kubernetes Invalid Alertmanager DNS"}
}

func NewKubernetesHostNetworkAlertmanagerClusterDNSFallbackAnalyzer() *KubernetesAlertmanagerDNSAnalyzer {
	return &KubernetesAlertmanagerDNSAnalyzer{id: KubernetesHostNetworkAlertmanagerClusterDNSFallbackID, name: "Kubernetes Host-Network Alertmanager Cluster DNS Fallback"}
}

func NewKubernetesAlertmanagerServiceLinksEnabledAnalyzer() *KubernetesAlertmanagerDNSAnalyzer {
	return &KubernetesAlertmanagerDNSAnalyzer{id: KubernetesAlertmanagerServiceLinksEnabledAnalyzerID, name: "Kubernetes Alertmanager Service Links Enabled"}
}

func (a *KubernetesAlertmanagerDNSAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerDNSAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerDNSAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerDNSAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerDNSAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_dns_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerDNSFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerDNSFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_dns_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidAlertmanagerDNSAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidAlertmanagerDNS"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d invalid DNS or ServiceLinks setting(s)", resource.Name, invalidCount)
		recommendation = "使用受支持的 DNSPolicy、合法 PodDNSConfig；dnsPolicy=None 时至少配置一个 IP nameserver，并使用布尔 enableServiceLinks。"
		metadata["alertmanager_dns_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesHostNetworkAlertmanagerClusterDNSFallbackID:
		if invalidCount > 0 || resource.Metadata["alertmanager_host_network_enabled"] != "true" || resource.Metadata["alertmanager_dns_policy_declared"] != "true" || resource.Metadata["alertmanager_dns_policy"] != "ClusterFirst" {
			return model.Finding{}, false
		}
		findingType = "KubernetesHostNetworkAlertmanagerClusterDNSFallback"
		evidence = fmt.Sprintf("Kubernetes host-network Alertmanager %q explicitly uses ClusterFirst, which falls back to node Default DNS", resource.Name)
		recommendation = "使用 ClusterFirstWithHostNet 保留集群 Service DNS；若不声明 dnsPolicy，Operator 会在 hostNetwork 场景自动选择该策略。"
		metadata["alertmanager_dns_policy"] = "ClusterFirst"
	case KubernetesAlertmanagerServiceLinksEnabledAnalyzerID:
		if invalidCount > 0 || resource.Metadata["alertmanager_service_links_declared"] != "true" || resource.Metadata["alertmanager_service_links_enabled"] != "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategorySecurity
		findingType = "KubernetesAlertmanagerServiceLinksEnabled"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q explicitly enables injection of namespace Service environment variables", resource.Name)
		recommendation = "设置 enableServiceLinks=false 并使用 Kubernetes DNS 发现服务，减少环境变量冲突、启动开销和不必要的 Service 拓扑暴露。"
		metadata["alertmanager_service_links_enabled"] = "true"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
