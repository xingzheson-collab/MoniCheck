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
	KubernetesInvalidThanosRulerImageAnalyzerID   = "builtin.kubernetes_invalid_thanos_ruler_image"
	KubernetesMutableThanosRulerImageAnalyzerID   = "builtin.kubernetes_mutable_thanos_ruler_image"
	KubernetesThanosRulerImagePullNeverAnalyzerID = "builtin.kubernetes_thanos_ruler_image_pull_never"
)

type KubernetesThanosRulerImageAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerImageAnalyzer() *KubernetesThanosRulerImageAnalyzer {
	return &KubernetesThanosRulerImageAnalyzer{id: KubernetesInvalidThanosRulerImageAnalyzerID, name: "Kubernetes Invalid ThanosRuler Image"}
}
func NewKubernetesMutableThanosRulerImageAnalyzer() *KubernetesThanosRulerImageAnalyzer {
	return &KubernetesThanosRulerImageAnalyzer{id: KubernetesMutableThanosRulerImageAnalyzerID, name: "Kubernetes Mutable ThanosRuler Image"}
}
func NewKubernetesThanosRulerImagePullNeverAnalyzer() *KubernetesThanosRulerImageAnalyzer {
	return &KubernetesThanosRulerImageAnalyzer{id: KubernetesThanosRulerImagePullNeverAnalyzerID, name: "Kubernetes ThanosRuler Image Pull Never"}
}

func (a *KubernetesThanosRulerImageAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerImageAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerImageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerImageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerImageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_image_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerImageFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerImageFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_image_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategorySecurity
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidThanosRulerImageAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidThanosRulerImage"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d invalid or unsupported image setting(s)", resource.Name, invalidCount)
		recommendation = "使用合法 OCI image、Always/IfNotPresent/Never 拉取策略和唯一非空 imagePullSecret 名称，并删除 ThanosRuler CRD 不支持的 baseImage/tag/sha。"
		metadata["thanos_ruler_image_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
		metadata["thanos_ruler_unsupported_legacy_image_field_count"] = resource.Metadata["thanos_ruler_unsupported_legacy_image_field_count"]
	case KubernetesMutableThanosRulerImageAnalyzerID:
		if invalidCount > 0 || resource.Metadata["thanos_ruler_image_declared"] != "true" || resource.Metadata["thanos_ruler_image_valid"] != "true" || resource.Metadata["thanos_ruler_image_digest_pinned"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesMutableThanosRulerImage"
		latest := resource.Metadata["thanos_ruler_image_latest_tag"] == "true"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q uses an explicit mutable image reference (latest-or-untagged=%t)", resource.Name, latest)
		recommendation = "将 spec.image 固定到经过验证的 sha256 digest，由受控发布流程显式更新 digest，避免标签漂移导致副本版本不一致。"
		metadata["thanos_ruler_image_latest_tag"] = fmt.Sprintf("%t", latest)
	case KubernetesThanosRulerImagePullNeverAnalyzerID:
		if invalidCount > 0 || resource.Metadata["thanos_ruler_image_pull_policy_valid"] != "true" || resource.Metadata["thanos_ruler_image_pull_policy"] != "Never" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesThanosRulerImagePullNever"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q uses imagePullPolicy Never, requiring every eligible node to have all images preloaded", resource.Name)
		recommendation = "使用 digest-pinned image 配合 IfNotPresent，或验证所有当前及扩容节点均有可靠的预拉取与镜像垃圾回收豁免流程。"
		metadata["thanos_ruler_image_pull_policy"] = "Never"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
