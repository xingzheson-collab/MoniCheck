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
	KubernetesInvalidThanosRulerDNSAnalyzerID          = "builtin.kubernetes_invalid_thanos_ruler_dns"
	KubernetesThanosRulerServiceLinksEnabledAnalyzerID = "builtin.kubernetes_thanos_ruler_service_links_enabled"
)

type KubernetesThanosRulerDNSAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerDNSAnalyzer() *KubernetesThanosRulerDNSAnalyzer {
	return &KubernetesThanosRulerDNSAnalyzer{id: KubernetesInvalidThanosRulerDNSAnalyzerID, name: "Kubernetes Invalid ThanosRuler DNS"}
}
func NewKubernetesThanosRulerServiceLinksEnabledAnalyzer() *KubernetesThanosRulerDNSAnalyzer {
	return &KubernetesThanosRulerDNSAnalyzer{id: KubernetesThanosRulerServiceLinksEnabledAnalyzerID, name: "Kubernetes ThanosRuler Service Links Enabled"}
}

func (a *KubernetesThanosRulerDNSAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerDNSAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerDNSAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerDNSAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerDNSAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_dns_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerDNSFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerDNSFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_dns_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategorySecurity
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidThanosRulerDNSAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidThanosRulerDNS"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d invalid or unsupported DNS/network setting(s)", resource.Name, invalidCount)
		recommendation = "使用受支持的 DNSPolicy 和合法 PodDNSConfig；dnsPolicy=None 时至少配置一个 IP nameserver，使用布尔 enableServiceLinks，并删除 ThanosRuler CRD 不支持的 hostNetwork。"
		metadata["thanos_ruler_dns_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
		metadata["thanos_ruler_host_network_unsupported"] = resource.Metadata["thanos_ruler_host_network_unsupported"]
	case KubernetesThanosRulerServiceLinksEnabledAnalyzerID:
		if invalidCount > 0 || resource.Metadata["thanos_ruler_service_links_declared"] != "true" || resource.Metadata["thanos_ruler_service_links_enabled"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesThanosRulerServiceLinksEnabled"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q explicitly enables injection of namespace Service environment variables", resource.Name)
		recommendation = "设置 enableServiceLinks=false 并使用 Kubernetes DNS 发现服务，减少环境变量冲突、启动开销和不必要的 Service 拓扑暴露。"
		metadata["thanos_ruler_service_links_enabled"] = "true"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
