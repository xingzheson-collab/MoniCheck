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
	KubernetesInvalidPrometheusImageAnalyzerID          = "builtin.kubernetes_invalid_prometheus_image"
	KubernetesDeprecatedPrometheusImageFieldsAnalyzerID = "builtin.kubernetes_deprecated_prometheus_image_fields"
	KubernetesMutablePrometheusImageAnalyzerID          = "builtin.kubernetes_mutable_prometheus_image"
	KubernetesPrometheusImagePullNeverAnalyzerID        = "builtin.kubernetes_prometheus_image_pull_never"
)

type KubernetesPrometheusImageAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusImageAnalyzer() *KubernetesPrometheusImageAnalyzer {
	return &KubernetesPrometheusImageAnalyzer{id: KubernetesInvalidPrometheusImageAnalyzerID, name: "Kubernetes Invalid Prometheus Image"}
}

func NewKubernetesDeprecatedPrometheusImageFieldsAnalyzer() *KubernetesPrometheusImageAnalyzer {
	return &KubernetesPrometheusImageAnalyzer{id: KubernetesDeprecatedPrometheusImageFieldsAnalyzerID, name: "Kubernetes Deprecated Prometheus Image Fields"}
}

func NewKubernetesMutablePrometheusImageAnalyzer() *KubernetesPrometheusImageAnalyzer {
	return &KubernetesPrometheusImageAnalyzer{id: KubernetesMutablePrometheusImageAnalyzerID, name: "Kubernetes Mutable Prometheus Image"}
}

func NewKubernetesPrometheusImagePullNeverAnalyzer() *KubernetesPrometheusImageAnalyzer {
	return &KubernetesPrometheusImageAnalyzer{id: KubernetesPrometheusImagePullNeverAnalyzerID, name: "Kubernetes Prometheus Image Pull Never"}
}

func (a *KubernetesPrometheusImageAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusImageAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusImageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusImageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusImageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (resource.Metadata["kubernetes_kind"] != "Prometheus" && resource.Metadata["kubernetes_kind"] != "PrometheusAgent") || resource.Metadata["prometheus_image_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusImageFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusImageFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := prometheusStorageMetadataInt64(resource, "prometheus_image_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategorySecurity
	findingType := ""
	evidence := ""
	recommendation := ""
	kind := resource.Metadata["kubernetes_kind"]
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidPrometheusImageAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusImage"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d invalid image setting(s)", kind, resource.Name, invalidCount)
		recommendation = "使用合法 OCI 镜像引用、Always/IfNotPresent/Never 拉取策略，并为每个 imagePullSecret 配置唯一非空名称。"
		metadata["prometheus_image_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesDeprecatedPrometheusImageFieldsAnalyzerID:
		legacyCount := prometheusStorageMetadataInt64(resource, "prometheus_legacy_image_field_count")
		if invalidCount > 0 || legacyCount == 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryLifecycle
		findingType = "KubernetesDeprecatedPrometheusImageFields"
		shadowedCount := prometheusStorageMetadataInt64(resource, "prometheus_shadowed_legacy_image_field_count")
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d deprecated image field(s), of which %d are shadowed by spec.image", kind, resource.Name, legacyCount, shadowedCount)
		recommendation = "将 baseImage/tag/sha 合并为唯一 spec.image 引用，并使用 digest pin 后删除旧字段。"
		metadata["prometheus_legacy_image_field_count"] = fmt.Sprintf("%d", legacyCount)
		metadata["prometheus_shadowed_legacy_image_field_count"] = fmt.Sprintf("%d", shadowedCount)
	case KubernetesMutablePrometheusImageAnalyzerID:
		if invalidCount > 0 || resource.Metadata["prometheus_image_declared"] != "true" || resource.Metadata["prometheus_image_valid"] != "true" || resource.Metadata["prometheus_image_digest_pinned"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesMutablePrometheusImage"
		latest := resource.Metadata["prometheus_image_latest_tag"] == "true"
		evidence = fmt.Sprintf("Kubernetes %s %q uses an explicit mutable image reference (latest-or-untagged=%t)", kind, resource.Name, latest)
		recommendation = "将 spec.image 固定到经过验证的 sha256 digest，由受控发布流程显式更新 digest，避免标签漂移导致副本版本不一致。"
		metadata["prometheus_image_latest_tag"] = fmt.Sprintf("%t", latest)
	case KubernetesPrometheusImagePullNeverAnalyzerID:
		if invalidCount > 0 || resource.Metadata["prometheus_image_pull_policy_valid"] != "true" || resource.Metadata["prometheus_image_pull_policy"] != "Never" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesPrometheusImagePullNever"
		evidence = fmt.Sprintf("Kubernetes %s %q uses imagePullPolicy Never, requiring every eligible node to have all images preloaded", kind, resource.Name)
		recommendation = "使用 digest-pinned image 配合 IfNotPresent，或验证所有节点和扩容节点均有可靠的预拉取与镜像垃圾回收豁免流程。"
		metadata["prometheus_image_pull_policy"] = "Never"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
