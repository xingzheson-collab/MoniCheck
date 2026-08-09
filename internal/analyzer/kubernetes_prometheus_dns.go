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
	KubernetesInvalidPrometheusDNSAnalyzerID            = "builtin.kubernetes_invalid_prometheus_dns"
	KubernetesHostNetworkPrometheusClusterDNSFallbackID = "builtin.kubernetes_host_network_prometheus_cluster_dns_fallback"
	KubernetesPrometheusServiceLinksEnabledAnalyzerID   = "builtin.kubernetes_prometheus_service_links_enabled"
)

type KubernetesPrometheusDNSAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusDNSAnalyzer() *KubernetesPrometheusDNSAnalyzer {
	return &KubernetesPrometheusDNSAnalyzer{id: KubernetesInvalidPrometheusDNSAnalyzerID, name: "Kubernetes Invalid Prometheus DNS"}
}

func NewKubernetesHostNetworkPrometheusClusterDNSFallbackAnalyzer() *KubernetesPrometheusDNSAnalyzer {
	return &KubernetesPrometheusDNSAnalyzer{id: KubernetesHostNetworkPrometheusClusterDNSFallbackID, name: "Kubernetes Host-Network Prometheus Cluster DNS Fallback"}
}

func NewKubernetesPrometheusServiceLinksEnabledAnalyzer() *KubernetesPrometheusDNSAnalyzer {
	return &KubernetesPrometheusDNSAnalyzer{id: KubernetesPrometheusServiceLinksEnabledAnalyzerID, name: "Kubernetes Prometheus Service Links Enabled"}
}

func (a *KubernetesPrometheusDNSAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusDNSAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusDNSAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusDNSAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusDNSAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (resource.Metadata["kubernetes_kind"] != "Prometheus" && resource.Metadata["kubernetes_kind"] != "PrometheusAgent") || resource.Metadata["prometheus_dns_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusDNSFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusDNSFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := prometheusStorageMetadataInt64(resource, "prometheus_dns_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	findingType := ""
	evidence := ""
	recommendation := ""
	kind := resource.Metadata["kubernetes_kind"]
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidPrometheusDNSAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusDNS"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d invalid host-network, DNS, or ServiceLinks setting(s)", kind, resource.Name, invalidCount)
		recommendation = "使用布尔 hostNetwork/enableServiceLinks、受支持的 DNSPolicy 和合法 PodDNSConfig；dnsPolicy=None 时至少配置一个 IP nameserver。"
		metadata["prometheus_dns_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesHostNetworkPrometheusClusterDNSFallbackID:
		if invalidCount > 0 || resource.Metadata["prometheus_host_network_enabled"] != "true" || resource.Metadata["prometheus_dns_policy_declared"] != "true" || resource.Metadata["prometheus_dns_policy"] != "ClusterFirst" {
			return model.Finding{}, false
		}
		findingType = "KubernetesHostNetworkPrometheusClusterDNSFallback"
		evidence = fmt.Sprintf("Kubernetes host-network %s %q explicitly uses ClusterFirst, which falls back to node Default DNS", kind, resource.Name)
		recommendation = "使用 ClusterFirstWithHostNet 保留集群 Service DNS；若不声明 dnsPolicy，Operator 会在 hostNetwork 场景自动选择该策略。"
		metadata["prometheus_dns_policy"] = "ClusterFirst"
	case KubernetesPrometheusServiceLinksEnabledAnalyzerID:
		if invalidCount > 0 || resource.Metadata["prometheus_service_links_declared"] != "true" || resource.Metadata["prometheus_service_links_enabled"] != "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategorySecurity
		findingType = "KubernetesPrometheusServiceLinksEnabled"
		evidence = fmt.Sprintf("Kubernetes %s %q explicitly enables injection of namespace Service environment variables", kind, resource.Name)
		recommendation = "设置 enableServiceLinks=false 并使用 Kubernetes DNS 发现服务，减少环境变量冲突、启动开销和不必要的 Service 拓扑暴露。"
		metadata["prometheus_service_links_enabled"] = "true"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
