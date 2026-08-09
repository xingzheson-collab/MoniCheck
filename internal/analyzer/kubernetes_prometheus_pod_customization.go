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
	KubernetesInvalidPrometheusPodCustomizationAnalyzerID = "builtin.kubernetes_invalid_prometheus_pod_customization"
	KubernetesPrometheusReservedPodMetadataAnalyzerID     = "builtin.kubernetes_prometheus_reserved_pod_metadata"
	KubernetesPrometheusHostAliasesAnalyzerID             = "builtin.kubernetes_prometheus_host_aliases"
)

type KubernetesPrometheusPodCustomizationAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusPodCustomizationAnalyzer() *KubernetesPrometheusPodCustomizationAnalyzer {
	return &KubernetesPrometheusPodCustomizationAnalyzer{id: KubernetesInvalidPrometheusPodCustomizationAnalyzerID, name: "Kubernetes Invalid Prometheus Pod Customization"}
}

func NewKubernetesPrometheusReservedPodMetadataAnalyzer() *KubernetesPrometheusPodCustomizationAnalyzer {
	return &KubernetesPrometheusPodCustomizationAnalyzer{id: KubernetesPrometheusReservedPodMetadataAnalyzerID, name: "Kubernetes Prometheus Reserved Pod Metadata"}
}

func NewKubernetesPrometheusHostAliasesAnalyzer() *KubernetesPrometheusPodCustomizationAnalyzer {
	return &KubernetesPrometheusPodCustomizationAnalyzer{id: KubernetesPrometheusHostAliasesAnalyzerID, name: "Kubernetes Prometheus Host Aliases"}
}

func (a *KubernetesPrometheusPodCustomizationAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusPodCustomizationAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusPodCustomizationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusPodCustomizationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusPodCustomizationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_pod_customization_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusPodCustomizationFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusPodCustomizationFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := prometheusStorageMetadataInt64(resource, "prometheus_pod_customization_invalid_setting_count")
	kind := resource.Metadata["kubernetes_kind"]
	findingType := ""
	evidence := ""
	recommendation := ""
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidPrometheusPodCustomizationAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusPodCustomization"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d invalid Pod metadata or HostAlias setting(s)", kind, resource.Name, invalidCount)
		recommendation = "使用合法 Kubernetes 标签/注解键值、IP 地址和唯一 DNS-1123 主机名，并通过 CRD/admission 校验清单。"
		metadata["prometheus_pod_customization_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesPrometheusReservedPodMetadataAnalyzerID:
		labelCount := prometheusStorageMetadataInt64(resource, "prometheus_reserved_label_override_count")
		annotationCount := prometheusStorageMetadataInt64(resource, "prometheus_reserved_annotation_override_count")
		if invalidCount > 0 || labelCount+annotationCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesPrometheusReservedPodMetadata"
		evidence = fmt.Sprintf("Kubernetes %s %q attempts to set %d Operator-reserved Pod label(s) and %d reserved annotation(s)", kind, resource.Name, labelCount, annotationCount)
		recommendation = "删除 podMetadata 中由 Prometheus Operator 管理的身份、版本、managed-by 和 default-container 键，改用组织自有前缀。"
		metadata["prometheus_reserved_label_override_count"] = fmt.Sprintf("%d", labelCount)
		metadata["prometheus_reserved_annotation_override_count"] = fmt.Sprintf("%d", annotationCount)
	case KubernetesPrometheusHostAliasesAnalyzerID:
		aliasCount := prometheusStorageMetadataInt64(resource, "prometheus_host_alias_count")
		if invalidCount > 0 || aliasCount == 0 {
			return model.Finding{}, false
		}
		hostnameCount := prometheusStorageMetadataInt64(resource, "prometheus_host_alias_hostname_count")
		loopbackCount := prometheusStorageMetadataInt64(resource, "prometheus_loopback_host_alias_count")
		findingType = "KubernetesPrometheusHostAliases"
		evidence = fmt.Sprintf("Kubernetes %s %q injects %d static /etc/hosts entries covering %d hostname(s), with %d loopback mapping(s)", kind, resource.Name, aliasCount, hostnameCount, loopbackCount)
		recommendation = "优先使用 Kubernetes Service/DNS；保留 hostAliases 时记录所有权、变更流程和失效监控，并确认 loopback 映射不会绕过预期网络路径。"
		metadata["prometheus_host_alias_count"] = fmt.Sprintf("%d", aliasCount)
		metadata["prometheus_host_alias_hostname_count"] = fmt.Sprintf("%d", hostnameCount)
		metadata["prometheus_loopback_host_alias_count"] = fmt.Sprintf("%d", loopbackCount)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
