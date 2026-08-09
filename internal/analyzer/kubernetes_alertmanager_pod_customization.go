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
	KubernetesInvalidAlertmanagerPodCustomizationAnalyzerID = "builtin.kubernetes_invalid_alertmanager_pod_customization"
	KubernetesAlertmanagerReservedPodMetadataAnalyzerID     = "builtin.kubernetes_alertmanager_reserved_pod_metadata"
	KubernetesAlertmanagerHostAliasesAnalyzerID             = "builtin.kubernetes_alertmanager_host_aliases"
)

type KubernetesAlertmanagerPodCustomizationAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerPodCustomizationAnalyzer() *KubernetesAlertmanagerPodCustomizationAnalyzer {
	return &KubernetesAlertmanagerPodCustomizationAnalyzer{id: KubernetesInvalidAlertmanagerPodCustomizationAnalyzerID, name: "Kubernetes Invalid Alertmanager Pod Customization"}
}

func NewKubernetesAlertmanagerReservedPodMetadataAnalyzer() *KubernetesAlertmanagerPodCustomizationAnalyzer {
	return &KubernetesAlertmanagerPodCustomizationAnalyzer{id: KubernetesAlertmanagerReservedPodMetadataAnalyzerID, name: "Kubernetes Alertmanager Reserved Pod Metadata"}
}

func NewKubernetesAlertmanagerHostAliasesAnalyzer() *KubernetesAlertmanagerPodCustomizationAnalyzer {
	return &KubernetesAlertmanagerPodCustomizationAnalyzer{id: KubernetesAlertmanagerHostAliasesAnalyzerID, name: "Kubernetes Alertmanager Host Aliases"}
}

func (a *KubernetesAlertmanagerPodCustomizationAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerPodCustomizationAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerPodCustomizationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerPodCustomizationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerPodCustomizationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_pod_customization_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerPodCustomizationFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerPodCustomizationFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_pod_customization_invalid_setting_count")
	findingType := ""
	evidence := ""
	recommendation := ""
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidAlertmanagerPodCustomizationAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidAlertmanagerPodCustomization"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d invalid Pod metadata or HostAlias setting(s)", resource.Name, invalidCount)
		recommendation = "使用合法 Kubernetes 标签/注解键值、IP 地址和唯一 DNS-1123 主机名，并通过 CRD/admission 校验清单。"
		metadata["alertmanager_pod_customization_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesAlertmanagerReservedPodMetadataAnalyzerID:
		labelCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_reserved_label_override_count")
		annotationCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_reserved_annotation_override_count")
		if invalidCount > 0 || labelCount+annotationCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesAlertmanagerReservedPodMetadata"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q attempts to set %d Operator-reserved Pod label(s) and %d reserved annotation(s)", resource.Name, labelCount, annotationCount)
		recommendation = "删除 podMetadata 中由 Prometheus Operator 管理的 Alertmanager 身份、版本、managed-by 和 default-container 键，改用组织自有前缀。"
		metadata["alertmanager_reserved_label_override_count"] = fmt.Sprintf("%d", labelCount)
		metadata["alertmanager_reserved_annotation_override_count"] = fmt.Sprintf("%d", annotationCount)
	case KubernetesAlertmanagerHostAliasesAnalyzerID:
		aliasCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_host_alias_count")
		if invalidCount > 0 || aliasCount == 0 {
			return model.Finding{}, false
		}
		hostnameCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_host_alias_hostname_count")
		loopbackCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_loopback_host_alias_count")
		findingType = "KubernetesAlertmanagerHostAliases"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q injects %d static /etc/hosts entries covering %d hostname(s), with %d loopback mapping(s)", resource.Name, aliasCount, hostnameCount, loopbackCount)
		recommendation = "优先使用 Kubernetes Service/DNS；保留 hostAliases 时记录所有权、变更流程和失效监控，并确认 loopback 映射不会绕过预期网络路径。"
		metadata["alertmanager_host_alias_count"] = fmt.Sprintf("%d", aliasCount)
		metadata["alertmanager_host_alias_hostname_count"] = fmt.Sprintf("%d", hostnameCount)
		metadata["alertmanager_loopback_host_alias_count"] = fmt.Sprintf("%d", loopbackCount)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
