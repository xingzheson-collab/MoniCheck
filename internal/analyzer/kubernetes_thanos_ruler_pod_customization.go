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
	KubernetesInvalidThanosRulerPodCustomizationAnalyzerID = "builtin.kubernetes_invalid_thanos_ruler_pod_customization"
	KubernetesThanosRulerReservedPodMetadataAnalyzerID     = "builtin.kubernetes_thanos_ruler_reserved_pod_metadata"
	KubernetesThanosRulerHostAliasesAnalyzerID             = "builtin.kubernetes_thanos_ruler_host_aliases"
)

type KubernetesThanosRulerPodCustomizationAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerPodCustomizationAnalyzer() *KubernetesThanosRulerPodCustomizationAnalyzer {
	return &KubernetesThanosRulerPodCustomizationAnalyzer{id: KubernetesInvalidThanosRulerPodCustomizationAnalyzerID, name: "Kubernetes Invalid ThanosRuler Pod Customization"}
}

func NewKubernetesThanosRulerReservedPodMetadataAnalyzer() *KubernetesThanosRulerPodCustomizationAnalyzer {
	return &KubernetesThanosRulerPodCustomizationAnalyzer{id: KubernetesThanosRulerReservedPodMetadataAnalyzerID, name: "Kubernetes ThanosRuler Reserved Pod Metadata"}
}

func NewKubernetesThanosRulerHostAliasesAnalyzer() *KubernetesThanosRulerPodCustomizationAnalyzer {
	return &KubernetesThanosRulerPodCustomizationAnalyzer{id: KubernetesThanosRulerHostAliasesAnalyzerID, name: "Kubernetes ThanosRuler Host Aliases"}
}

func (a *KubernetesThanosRulerPodCustomizationAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerPodCustomizationAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerPodCustomizationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerPodCustomizationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerPodCustomizationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_pod_customization_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerPodCustomizationFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerPodCustomizationFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_pod_customization_invalid_setting_count")
	findingType := ""
	evidence := ""
	recommendation := ""
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidThanosRulerPodCustomizationAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidThanosRulerPodCustomization"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d invalid Pod metadata or HostAlias setting(s)", resource.Name, invalidCount)
		recommendation = "使用合法 Kubernetes 标签/注解键值、IP 地址和唯一 DNS-1123 主机名，并通过 CRD/admission 校验清单。"
		metadata["thanos_ruler_pod_customization_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesThanosRulerReservedPodMetadataAnalyzerID:
		labelCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_reserved_label_override_count")
		annotationCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_reserved_annotation_override_count")
		if invalidCount > 0 || labelCount+annotationCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesThanosRulerReservedPodMetadata"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q attempts to set %d Operator-reserved Pod label(s) and %d reserved annotation(s)", resource.Name, labelCount, annotationCount)
		recommendation = "删除 podMetadata 中由 Prometheus Operator 管理的 ThanosRuler 身份、版本、managed-by 和 default-container 键，改用组织自有前缀。"
		metadata["thanos_ruler_reserved_label_override_count"] = fmt.Sprintf("%d", labelCount)
		metadata["thanos_ruler_reserved_annotation_override_count"] = fmt.Sprintf("%d", annotationCount)
	case KubernetesThanosRulerHostAliasesAnalyzerID:
		aliasCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_host_alias_count")
		if invalidCount > 0 || aliasCount == 0 {
			return model.Finding{}, false
		}
		hostnameCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_host_alias_hostname_count")
		loopbackCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_loopback_host_alias_count")
		findingType = "KubernetesThanosRulerHostAliases"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q injects %d static /etc/hosts entries covering %d hostname(s), with %d loopback mapping(s)", resource.Name, aliasCount, hostnameCount, loopbackCount)
		recommendation = "优先使用 Kubernetes Service/DNS；保留 hostAliases 时记录所有权、变更流程和失效监控，并确认 loopback 映射不会绕过预期网络路径。"
		metadata["thanos_ruler_host_alias_count"] = fmt.Sprintf("%d", aliasCount)
		metadata["thanos_ruler_host_alias_hostname_count"] = fmt.Sprintf("%d", hostnameCount)
		metadata["thanos_ruler_loopback_host_alias_count"] = fmt.Sprintf("%d", loopbackCount)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
